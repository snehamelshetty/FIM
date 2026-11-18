"""
OPTIONAL helper: turns terminal output (docs/*.txt) into PNG "screenshots".
    python tools/make_terminal_screenshots.py
"""
import re
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 15)
BG, FG, ACCENT = (24, 26, 33), (220, 223, 228), (120, 200, 255)
WIDTH_CHARS = 118


def render(lines, out_path, title):
    wrapped = []
    for line in lines:
        wrapped += textwrap.wrap(line, WIDTH_CHARS, replace_whitespace=False, subsequent_indent="      ") or [""]
    line_h = 20
    img = Image.new("RGB", (1120, 60 + line_h * len(wrapped) + 20), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, 1120, 36], fill=(45, 48, 58))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([14 + i * 22, 11, 26 + i * 22, 23], fill=c)
    d.text((100, 9), title, font=FONT, fill=(190, 195, 205))
    y = 52
    for line in wrapped:
        color = FG
        if "SCENARIO" in line or line.startswith("====="):
            color = ACCENT
        elif re.search(r"\[(HIGH|CRITICAL)\]| ERROR |CRITICAL", line):
            color = (255, 110, 110)
        elif re.search(r"\[MEDIUM\]| WARNING ", line):
            color = (255, 205, 90)
        elif line.strip().endswith("OK") or " ... ok" in line:
            color = (120, 220, 130)
        d.text((16, y), line, font=FONT, fill=color)
        y += line_h
    img.save(out_path)


def main():
    out = ROOT / "screenshots"
    out.mkdir(exist_ok=True)
    tests = (ROOT / "docs" / "unittest_output.txt").read_text().splitlines()
    render(tests, out / "09_unit_tests_all_passing.png", "python -m unittest discover -s tests -t . -v")

    transcript = (ROOT / "docs" / "test_transcript.txt").read_text().splitlines()
    sections, current = [], []
    for line in transcript:
        if line.startswith("SCENARIO") and current:
            sections.append(current)
            current = []
        current.append(line)
    sections.append(current)
    sections = [sec for sec in sections if any(l.startswith('SCENARIO') for l in sec)]  # drop preamble
    groups = {"10_scenarios_1-3_baseline_modify_detect": (0, 3), "11_scenarios_4-5b_delete_create_rename": (3, 6),
              "12_scenarios_6-6b_approve_and_baseline_tamper": (6, 8), "13_scenario_7_logs_and_report": (8, 9),
              "14_scenario_8_realtime_watchdog": (9, 10)}
    for name, (a, b) in groups.items():
        lines = [l for sec in sections[a:b] for l in sec if not l.startswith("====")]
        lines = [l for l in lines if l.strip() != ""] if "13" in name else lines
        render(lines, out / f"{name}.png", "python demo_scenarios.py")
    print("terminal screenshots written")


if __name__ == "__main__":
    main()
