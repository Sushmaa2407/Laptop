import numpy as np
import sklearn, skl2onnx, onnxruntime as ort
from sklearn.ensemble import IsolationForest
from skl2onnx import to_onnx

print("versions:", "sklearn", sklearn.__version__, "| skl2onnx", skl2onnx.__version__, "| onnxruntime", ort.__version__)

rng = np.random.default_rng(42)
X_train = rng.normal(size=(5000, 14)).astype(np.float32)
# 100 normal rows followed by 20 clearly anomalous rows
X_test = np.vstack([rng.normal(size=(100, 14)),
                    rng.normal(loc=6.0, size=(20, 14))]).astype(np.float32)

model = IsolationForest(n_estimators=100, random_state=42).fit(X_train)

try:
    onx = to_onnx(model, X_train[:1], target_opset={"": 15, "ai.onnx.ml": 3})
except Exception as e:
    print("conversion with explicit opset failed:", e)
    onx = to_onnx(model, X_train[:1])

sess = ort.InferenceSession(onx.SerializeToString(), providers=["CPUExecutionProvider"])
in_name = sess.get_inputs()[0].name
names = [o.name for o in sess.get_outputs()]
print("ONNX input:", in_name, "| outputs:", names)

outs = dict(zip(names, sess.run(None, {in_name: X_test})))

def ranks(a):
    return np.argsort(np.argsort(a))

sk_pred = model.predict(X_test)
sk_ss = model.score_samples(X_test)
sk_df = model.decision_function(X_test)

for name, arr in outs.items():
    arr = np.asarray(arr).ravel()
    print("\n--- output:", name, "dtype:", arr.dtype, "shape:", arr.shape)
    if arr.dtype.kind in "iu":
        print("labels equal to sklearn predict:", np.mean(arr == sk_pred))
    else:
        print("mean on normal rows:", arr[:100].mean(), "| mean on anomalies:", arr[100:].mean())
        for label, ref in [("score_samples", sk_ss), ("decision_function", sk_df)]:
            print(f"vs {label}: max abs diff = {np.max(np.abs(arr - ref)):.6f}, "
                  f"rank correlation = {np.corrcoef(ranks(arr), ranks(ref))[0,1]:.4f}")
