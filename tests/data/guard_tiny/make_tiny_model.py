"""Builds the tiny TEST model in this folder (not Prompt Guard; no Meta material): same inputs/outputs as the real
export (input_ids, attention_mask -> logits[batch, 2]) and a word-level tokenizer. The "malicious" logit is
10 x (number of 'ignore' tokens) - 5, so any text containing the word "ignore" scores ~1.0 and other text ~0.007.
Used by tests/test_guard.py and the E2E check. Needs the `onnx` package (not a Goose Web dependency):
    python tests/data/guard_tiny/make_tiny_model.py
"""
import json
from pathlib import Path

import onnx
from onnx import TensorProto, helper

HERE = Path(__file__).resolve().parent
VOCAB = ["[PAD]", "[CLS]", "[SEP]", "[UNK]", "ignore", "all", "previous", "instructions", "and", "the", "what", "is",
         "weather", "in", "paris", "print", "your", "system", "prompt", "run", "search", "index", "main", "stats",
         "count", "by", "user"]
IGNORE_ID = VOCAB.index("ignore")

g = helper.make_graph(
    [helper.make_node("Constant", [], ["tgt"], value=helper.make_tensor("t", TensorProto.INT64, [], [IGNORE_ID])),
     helper.make_node("Equal", ["input_ids", "tgt"], ["eq"]),
     helper.make_node("Cast", ["eq"], ["eqf"], to=TensorProto.FLOAT),
     helper.make_node("Cast", ["attention_mask"], ["mf"], to=TensorProto.FLOAT),
     helper.make_node("Mul", ["eqf", "mf"], ["hits"]),
     helper.make_node("Constant", [], ["ax"], value=helper.make_tensor("a", TensorProto.INT64, [1], [1])),
     helper.make_node("ReduceSum", ["hits", "ax"], ["n"], keepdims=1),
     helper.make_node("Constant", [], ["ten"], value=helper.make_tensor("ten_v", TensorProto.FLOAT, [], [10.0])),
     helper.make_node("Constant", [], ["five"], value=helper.make_tensor("five_v", TensorProto.FLOAT, [], [5.0])),
     helper.make_node("Mul", ["n", "ten"], ["n10"]),
     helper.make_node("Sub", ["n10", "five"], ["mal"]),
     helper.make_node("Mul", ["n", "five"], ["z0"]),
     helper.make_node("Sub", ["z0", "z0"], ["benign"]),
     helper.make_node("Concat", ["benign", "mal"], ["logits"], axis=1)],
    "tiny_guard",
    [helper.make_tensor_value_info("input_ids", TensorProto.INT64, ["batch", "sequence"]),
     helper.make_tensor_value_info("attention_mask", TensorProto.INT64, ["batch", "sequence"])],
    [helper.make_tensor_value_info("logits", TensorProto.FLOAT, ["batch", 2])])
m = helper.make_model(g, opset_imports=[helper.make_opsetid("", 17)], producer_name="goose-web-tests")
m.ir_version = 8
onnx.checker.check_model(m)
onnx.save(m, str(HERE / "model.onnx"))
tok = {"version": "1.0", "truncation": None, "padding": None,
       "added_tokens": [{"id": i, "content": t, "single_word": False, "lstrip": False, "rstrip": False,
                         "normalized": False, "special": True} for i, t in enumerate(VOCAB[:4])],
       "normalizer": {"type": "Lowercase"}, "pre_tokenizer": {"type": "Whitespace"}, "post_processor": None,
       "decoder": None, "model": {"type": "WordLevel", "vocab": {t: i for i, t in enumerate(VOCAB)},
                                  "unk_token": "[UNK]"}}
(HERE / "tokenizer.json").write_text(json.dumps(tok, indent=1) + "\n", encoding="utf-8")
(HERE / "config.json").write_text(json.dumps({"model": "goose-web/tiny-test-model", "revision": "test",
                                              "id2label": {"0": "BENIGN", "1": "MALICIOUS"}, "malicious_index": 1,
                                              "proxy": True}, indent=2) + "\n", encoding="utf-8")
print("written", HERE)
