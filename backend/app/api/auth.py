"""Registration, login, token refresh, logout and /me."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, get_current_user, get_session
from app.api.schemas import LoginRequest, MeResponse, RegisterRequest, TokenResponse
from app.core import ratelimit, security
from app.core.config import Settings, get_settings
from app.db.models import User
from app.repositories import auth as auth_repo

router = APIRouter(prefix="/auth", tags=["auth"])
me_router = APIRouter(tags=["me"])

REFRESH_COOKIE = "refresh_token"
COOKIE_PATH = "/api/v1/auth"


def _bad_credentials() -> HTTPException:
    return HTTPException(status_code=401, detail="Invalid email or password")


def _bad_refresh() -> HTTPException:
    return HTTPException(status_code=401, detail="Invalid or expired session")


def _set_refresh_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        REFRESH_COOKIE,
        token,
        max_age=settings.refresh_token_days * 86400,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path=COOKIE_PATH,
    )


async def _issue_tokens(
    session: AsyncSession, user: User, response: Response, settings: Settings, audit_action: str | None = None
) -> TokenResponse:
    ttl = settings.access_token_minutes * 60
    access = security.create_access_token(
        user_id=user.id, tenant_id=user.tenant_id, secret=settings.jwt_secret, ttl_seconds=ttl
    )
    refresh_token, refresh_hash = security.new_opaque_token()
    auth_repo.add_refresh_token(session, user_id=user.id, token_hash=refresh_hash, ttl_days=settings.refresh_token_days)
    if audit_action:
        auth_repo.audit(session, user.tenant_id, str(user.id), audit_action)
    await session.commit()
    _set_refresh_cookie(response, refresh_token, settings)
    response.headers["Cache-Control"] = "no-store"
    return TokenResponse(access_token=access, expires_in=ttl)


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(
    body: RegisterRequest, request: Request, response: Response, session: AsyncSession = Depends(get_session)
):
    settings = get_settings()
    await ratelimit.hit(ratelimit.REGISTER_PER_IP, ratelimit.client_ip(request))
    try:
        security.validate_password_policy(body.password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if body.password.lower() == body.email:
        raise HTTPException(status_code=422, detail="password must not be the same as the email")
    password_hash = await security.hash_password(body.password)
    try:
        user = await auth_repo.create_tenant_and_user(
            session, tenant_name=body.tenant_name, email=body.email, password_hash=password_hash
        )
    except auth_repo.EmailTaken:
        raise HTTPException(status_code=409, detail="Email already registered") from None
    return await _issue_tokens(session, user, response, settings)


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, response: Response, session: AsyncSession = Depends(get_session)):
    settings = get_settings()
    ip = ratelimit.client_ip(request)
    await ratelimit.hit(ratelimit.LOGIN_PER_IP, ip)
    # Locked-out callers are refused BEFORE the password is checked, so a correct guess reveals nothing.
    await ratelimit.check(ratelimit.LOGIN_FAILS_PER_IP_EMAIL, ip, body.email)
    await ratelimit.check(ratelimit.LOGIN_FAILS_PER_EMAIL, body.email)

    user = await auth_repo.get_user_by_email(session, body.email)
    if user is None or not user.is_active:
        await security.verify_unknown_user(body.password)  # same time cost as a real check
        ok = False
    else:
        ok = await security.verify_password(user.password_hash, body.password)
    if not ok:
        await ratelimit.record(ratelimit.LOGIN_FAILS_PER_IP_EMAIL, ip, body.email)
        await ratelimit.record(ratelimit.LOGIN_FAILS_PER_EMAIL, body.email)
        raise _bad_credentials()
    await ratelimit.reset(ratelimit.LOGIN_FAILS_PER_IP_EMAIL, ip, body.email)
    return await _issue_tokens(session, user, response, settings, audit_action="user.login")


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: Request, response: Response, session: AsyncSession = Depends(get_session)):
    settings = get_settings()
    await ratelimit.hit(ratelimit.REFRESH_PER_IP, ratelimit.client_ip(request))
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        raise _bad_refresh()
    row = await auth_repo.get_refresh_token(session, security.hash_token(token), for_update=True)
    if row is None:
        raise _bad_refresh()
    now = auth_repo.utcnow()
    if row.revoked_at is not None:
        # An already-used token came back: assume it was stolen and end every session.
        await auth_repo.revoke_all_for_user(session, row.user_id)
        user = await auth_repo.get_user_by_id(session, row.user_id)
        if user is not None:
            auth_repo.audit(session, user.tenant_id, str(user.id), "token.reuse_detected")
        await session.commit()
        raise _bad_refresh()
    if row.expires_at <= now:
        raise _bad_refresh()
    user = await auth_repo.get_user_by_id(session, row.user_id)
    if user is None or not user.is_active:
        raise _bad_refresh()
    row.revoked_at = now  # rotate: the old token can never be used again
    return await _issue_tokens(session, user, response, settings)


@router.post("/logout", status_code=204)
async def logout(request: Request, session: AsyncSession = Depends(get_session)):
    token = request.cookies.get(REFRESH_COOKIE)
    if token:
        row = await auth_repo.get_refresh_token(session, security.hash_token(token))
        if row is not None and row.revoked_at is None:
            row.revoked_at = auth_repo.utcnow()
            await session.commit()
    response = Response(status_code=204)
    response.delete_cookie(REFRESH_COOKIE, path=COOKIE_PATH)
    return response


@me_router.get("/me", response_model=MeResponse)
async def me(current: CurrentUser = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    tenant = await auth_repo.get_tenant(session, current.tenant_id)
    return MeResponse(
        user_id=current.user_id,
        tenant_id=current.tenant_id,
        email=current.email,
        tenant_name=tenant.name if tenant else "",
    )
