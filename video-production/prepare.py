"""Prepare slide narration and timing, or render only the review sample."""

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NOTES = ROOT.parent / ".venv" / "agentguard-speaker-notes.md"
PREVIEW = ROOT.parent / ".venv" / "agentguard-recording.html"
TARGET_SECONDS = 570
WORDS_PER_MINUTE = 145
VOICE = "af_heart"


def timecode(seconds):
    return f"{seconds // 60}:{seconds % 60:02d}"


def narration():
    text = NOTES.read_text(encoding="utf-8")
    parts = re.split(r"(?m)^## (\d+)\. ([\w-]+)\s*$", text)
    rows = []
    for number, slide, note in zip(parts[1::3], parts[2::3], parts[3::3]):
        spoken = re.sub(r"^\[[^\]]+\]\s*", "", note.strip())
        if slide == "demo":
            spoken = spoken[spoken.index("First case:") : spoken.index(" FALLBACK")]
            spoken = spoken.replace(
                "The recorded model time on screen is a few seconds; say so. Press Enter.",
                "The model time on screen is from the original recorded calls.",
            )
        else:
            spoken = re.split(r" NEXT:| WHO ANSWERS:", spoken, maxsplit=1)[0]
        rows.append((int(number), slide, spoken))
    slide_ids = re.findall(r'<section\b[^>]*\bid="([\w-]+)"', PREVIEW.read_text(encoding="utf-8"))
    if len(rows) != 15 or [slide for _, slide, _ in rows] != slide_ids or slide_ids[-1] != "questions":
        raise ValueError("Speaker notes and recording preview are out of sync")
    return rows


def prepare():
    rows = narration()
    spoken_seconds = [round(len(text.split()) * 60 / WORDS_PER_MINUTE) for _, _, text in rows]
    demo = next(i for i, (_, slide, _) in enumerate(rows) if slide == "demo")
    # Allow at least 55 seconds for the slide-to-terminal handoff and two verdict holds.
    slots = [seconds + 2 for seconds in spoken_seconds]
    slots[demo] = max(55, slots[demo])
    remaining = TARGET_SECONDS - sum(slots)
    if remaining < 0:
        raise ValueError("Narration and demo allowance exceed the target")
    other_slides = [i for i in range(len(rows)) if i != demo]
    for i in range(remaining):
        slots[other_slides[i % len(other_slides)]] += 1

    script = ["# AgentGuard-LLM narration", "",
              "Extracted from the existing speaker notes. Presenter cues are omitted from the spoken text.", ""]
    plan = [
        "# Timing estimate", "",
        f"Target {timecode(TARGET_SECONDS)}. Estimates use {WORDS_PER_MINUTE} words per minute.",
        "Slide slots include pauses and transitions. Final timing needs a check against rendered audio.",
        "Production acceptance limit: total runtime strictly below 10:00.", "",
        "| Slide | Topic | Estimated speech | Planned slot | Timeline |",
        "|---:|---|---:|---:|---|",
    ]
    elapsed = 0
    for (number, slide, spoken), seconds, slot in zip(rows, spoken_seconds, slots):
        script.extend([f"## {number}. {slide}", "", spoken, ""])
        if slide == "demo":
            script.extend([
                "**Production cue** Switch to the terminal on slide 6. Hold on the blindspot verdict, "
                "advance to guard-attack, then return to the deck for slide 7.", "",
            ])
        plan.append(f"| {number} | {slide} | {seconds}s | {slot}s | {timecode(elapsed)}–{timecode(elapsed + slot)} |")
        if slide == "demo":
            demo_start, demo_end = elapsed, elapsed + slot
        elapsed += slot
    plan.extend([
        "", "## Slide 6 terminal insert", "",
        f"- {timecode(demo_start)}–{timecode(demo_start + 4)} — Show the existing demo slide.",
        f"- {timecode(demo_start + 4)}–{timecode(demo_start + 28)} — Show blindspot and hold on the two verdicts.",
        f"- {timecode(demo_start + 28)}–{timecode(demo_end - 4)} — Show guard-attack and hold on the LLM block.",
        f"- {timecode(demo_end - 4)}–{timecode(demo_end)} — Return to the slide deck before Method.",
        "", "Kokoro narration will carry across the terminal insert. The adaptive figures remain the project's recorded result.",
    ])
    (ROOT / "narration.md").write_text("\n".join(script), encoding="utf-8")
    (ROOT / "timing.md").write_text("\n".join(plan) + "\n", encoding="utf-8")


def sample():
    import soundfile
    from kokoro_onnx import Kokoro

    model_dir = ROOT / "models"
    kokoro = Kokoro(str(model_dir / "kokoro-v1.0.onnx"), str(model_dir / "voices-v1.0.bin"))
    cover = narration()[0][2]
    spoken = cover.split(" In one line:")[0] + " " + cover[cover.index("The honest result") :]
    audio, rate = kokoro.create(spoken, voice=VOICE, speed=1.0, lang="en-us")
    soundfile.write(ROOT / "voice-sample.wav", audio, rate, subtype="PCM_16")
    print(f"{VOICE}: {len(audio) / rate:.2f} seconds at {rate} Hz")
    (ROOT / "voice-sample.txt").write_text(spoken + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("step", choices=["prepare", "sample"])
    if parser.parse_args().step == "prepare":
        prepare()
    else:
        sample()
