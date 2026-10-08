"""Shared training/inference normalization and bounded overlapping windows."""
import re
import unicodedata

def normalize_arabic_text(text: str) -> str:
    if not isinstance(text, str):
        return ''
    # Equivalent letter normalizations to the original camel-tools preparation.
    text = ''.join(c for c in text if not ('ARABIC' in unicodedata.name(c, '') and unicodedata.category(c) == 'Mn'))
    return text.translate(str.maketrans({'أ':'ا', 'إ':'ا', 'آ':'ا', 'ٱ':'ا', 'ى':'ي', 'ة':'ه'}))

def text_windows(text: str, size: int = 150, stride: int = 75):
    words = text.split()
    if len(words) <= size:
        return [text]
    windows = []
    for start in range(0, len(words), stride):
        windows.append(' '.join(words[start:start+size]))
        if start + size >= len(words):
            break
    return windows
