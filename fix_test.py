p = "tests/test_fim.py"
s = open(p).read()
old = '        os.environ["FIM_DATA_DIR"] = str(tmp / "data")\n'
new = '        from fim import config\n        original_data_dir = config.DATA_DIR\n        config.DATA_DIR = (tmp / "data").resolve()\n'
assert old in s, "already patched or different file"
s = s.replace(old, new)
s = s.replace('            os.environ.pop("FIM_DATA_DIR", None)\n', '            config.DATA_DIR = original_data_dir\n')
open(p, "w").write(s)
print("patched OK")
