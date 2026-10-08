"""Rebuild grouped v2 splits instead of overwriting the September tokenizer and arrays."""
import runpy
from pathlib import Path
if __name__=='__main__':runpy.run_path(str(Path(__file__).resolve().parents[1]/'data/scripts/rebuild_dataset.py'),run_name='__main__')
