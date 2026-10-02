# ADR-004: Anomaly score convention
Decision: ONNX output "scores" equals sklearn decision_function (higher = more normal, anomalies negative). Read the output by name, never by position.
Alert threshold is chosen on a benign validation set and stored in the model manifest with this note.
Versions verified: sklearn 1.9.1, skl2onnx 1.20.0, onnxruntime 1.30.0.
