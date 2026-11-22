"""Render and measure the reviewed narration and build its caption timeline."""

import json
import os
import re
import subprocess
import textwrap
from pathlib import Path

# Keep short, repeated CPU inference runs from oversubscribing the machine.
os.environ.setdefault("OMP_NUM_THREADS", "2")

import numpy as np
import soundfile as sf
from kokoro_onnx import Kokoro

ROOT = Path(__file__).resolve().parent
AUDIO = ROOT / "slide-audio"
RATE = 24_000
TARGET = 570 * RATE
LIMIT = 600 * RATE
VOICE = "am_michael"
PRONUNCIATION = json.loads((ROOT / "pronunciation.json").read_text(encoding="utf-8-sig"))
PHONEME_OVERRIDES = PRONUNCIATION.pop("phoneme_overrides", {})
OVERRIDES = re.compile(
    r"(?<!\w)(?:" + "|".join(map(re.escape, sorted(PRONUNCIATION, key=len, reverse=True))) + r")(?!\w)",
    re.IGNORECASE,
)
SPOKEN = {key.casefold(): value for key, value in PRONUNCIATION.items()}


def slides():
    master = (ROOT / "narration.md").read_text(encoding="utf-8-sig")
    parts = re.split(r"(?m)^## (\d+)\. ([\w-]+)[ \t]*$", master)
    rows = []
    for number, name, body in zip(parts[1::3], parts[2::3], parts[3::3]):
        paragraphs = [p.strip() for p in re.split(r"\n\s*\n", body.strip())]
        text = " ".join(p for p in paragraphs if not p.startswith("**Production cue**"))
        rows.append((int(number), name, " ".join(text.split())))
    preview = ROOT.parent / ".venv" / "agentguard-recording.html"
    ids = re.findall(r'<section\b[^>]*\bid="([\w-]+)"', preview.read_text(encoding="utf-8"))
    if [number for number, _, _ in rows] != list(range(1, 16)) or [name for _, name, _ in rows] != ids:
        raise ValueError("Master narration and preview slide order differ")
    return rows


def phrases(text):
    sentences = re.split(r"(?<=[.!?])\s+", text)
    for sentence in sentences:
        while len(sentence) > 94:
            candidates = [m.end() for m in re.finditer(r"[,;:]\s+", sentence[:92]) if m.end() >= 38]
            if not candidates:
                candidates = [m.start() for m in re.finditer(r"\s+(?:and|but|so|because|with|which)\b", sentence[:92]) if m.start() >= 42]
            cut = candidates[-1] if candidates else sentence.rfind(" ", 45, 93)
            if cut < 0:
                break
            # Keep the short names and version strings together for TTS overrides.
            for match in OVERRIDES.finditer(sentence):
                if match.start() < cut < match.end():
                    cut = match.start() or match.end()
                    break
            yield sentence[:cut].strip(), False
            sentence = sentence[cut:].strip()
        if sentence:
            yield sentence, True


def silence(samples):
    return np.zeros(samples, dtype=np.float32)


def probe(path):
    result = subprocess.check_output([
        "ffprobe", "-v", "error", "-show_entries", "stream=sample_rate,duration_ts:format=duration",
        "-of", "json", str(path),
    ], text=True)
    info = json.loads(result)
    stream = info["streams"][0]
    if int(stream["sample_rate"]) != RATE:
        raise ValueError(f"Unexpected sample rate for {path.name}")
    return int(stream["duration_ts"]), float(info["format"]["duration"])


def render(kokoro, number, name, text):
    audio_parts, cues = [], []
    cursor = 0
    for index, (phrase, sentence_end) in enumerate(phrases(text)):
        pronunciation = OVERRIDES.sub(lambda match: SPOKEN[match[0].casefold()], phrase)
        if not sentence_end and pronunciation[-1] not in ",;:":
            pronunciation += ","
        use_phonemes = any(name in pronunciation for name in PHONEME_OVERRIDES)
        if use_phonemes:
            phonemes = kokoro.tokenizer.phonemize(pronunciation, lang="en-us")
            for name, replacement in PHONEME_OVERRIDES.items():
                if name in pronunciation:
                    default = kokoro.tokenizer.phonemize(name, lang="en-us")
                    if default not in phonemes:
                        raise ValueError(f"Could not apply phoneme override for {name}")
                    phonemes = phonemes.replace(default, replacement)
            pronunciation = phonemes
        audio, rate = kokoro.create(
            pronunciation, voice=VOICE, speed=1.0, lang="en-us", is_phonemes=use_phonemes
        )
        if rate != RATE or len(audio) == 0:
            raise ValueError(f"Unexpected Kokoro output on slide {number}, phrase {index + 1}")
        active = np.flatnonzero(np.abs(audio) >= 0.001)
        if not len(active):
            raise ValueError(f"Silent audio on slide {number}, phrase {index + 1}")
        written = re.sub(r"\bAgent Guard-LLM\b", "AgentGuard-LLM", phrase)
        cues.append((cursor + max(0, int(active[0]) - RATE // 50),
                     cursor + min(len(audio), int(active[-1]) + RATE // 12), written))
        audio_parts.append(audio)
        gap = round(RATE * (0.24 if sentence_end else 0.11))
        audio_parts.append(silence(gap))
        cursor += len(audio) + gap
    path = AUDIO / f"{number:02d}-{name}.wav"
    sf.write(path, np.concatenate(audio_parts), RATE, subtype="PCM_16")
    samples, seconds = probe(path)
    if samples != cursor:
        raise ValueError(f"Measured duration mismatch for {path.name}")
    print(f"{number:02d} {name}: {seconds:.3f}s, {len(cues)} aligned phrases", flush=True)
    return number, name, path, samples, cues


def stamp(samples, srt=False):
    ms = round(samples * 1000 / RATE)
    seconds, ms = divmod(ms, 1000)
    minutes, seconds = divmod(seconds, 60)
    if srt:
        hours, minutes = divmod(minutes, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d},{ms:03d}"
    return f"{minutes}:{seconds:02d}.{ms:03d}"


def timeline(rows):
    # The demo plays under its narration. Four seconds before and after give
    # room to show the original slide and make each window handoff.
    leads = [RATE // 2] * len(rows)
    tails = [RATE] * len(rows)
    demo_index = next(i for i, row in enumerate(rows) if row[1] == "demo")
    leads[demo_index] = 4 * RATE
    tails[demo_index] = 4 * RATE
    if rows[demo_index][3] + leads[demo_index] + tails[demo_index] < 55 * RATE:
        tails[demo_index] = 55 * RATE - rows[demo_index][3] - leads[demo_index]
    speech = sum(row[3] for row in rows)
    minimum = speech + sum(leads) + sum(tails)
    if minimum >= LIMIT:
        longest = sorted(rows, key=lambda row: row[3], reverse=True)[:5]
        durations = ", ".join(f"{row[0]} {row[1]} ({stamp(row[3])})" for row in longest)
        (ROOT / "timing.md").write_text(
            f"# Duration review required\n\nNarration {stamp(speech)}. "
            f"With required holds, {stamp(minimum)}. Longest sections: {durations}.\n",
            encoding="utf-8",
        )
        raise ValueError(f"Minimum runtime {stamp(minimum)}. Review these sections: {durations}")
    # Preserve speech speed. Allocate remaining runtime as reading holds on slides.
    slack = max(0, TARGET - minimum)
    hold_indices = [i for i in range(len(rows)) if i != demo_index]
    for position, i in enumerate(hold_indices):
        tails[i] += slack * (position + 1) // len(hold_indices) - slack * position // len(hold_indices)

    report = [
        "# Measured narration and video timing", "",
        f"- Voice: Kokoro `{VOICE}` at 1.0× throughout.",
        f"- Total measured slide narration: **{stamp(speech)}** including short phrase pauses.",
        f"- Minimum with demo and slide handoffs: **{stamp(minimum)}**.",
        f"- Projected runtime and timed audio preview: **{stamp(max(TARGET, minimum))}**. Strict limit: below 10:00.",
        "- Captions use the sample offsets of the rendered phrases and their measured audible bounds.",
        "- The terminal insert plays under slide 6 narration. No final video has been assembled.", "",
        "| Slide | Topic | WAV duration | Lead hold | End hold | Video timeline |",
        "|---:|---|---:|---:|---:|---|",
    ]
    captions, preview = [], []
    cursor = 0
    for i, (number, name, path, samples, cues) in enumerate(rows):
        audio, rate = sf.read(path, dtype="float32")
        if rate != RATE or len(audio) != samples:
            raise ValueError(f"Unexpected WAV length for {path.name}")
        lead, tail = leads[i], tails[i]
        speech_start = cursor + lead
        end = speech_start + samples + tail
        preview.extend([silence(lead), audio, silence(tail)])
        for start, stop, text in cues:
            captions.append(
                f"{len(captions) + 1}\n{stamp(speech_start + start, True)} --> "
                f"{stamp(speech_start + stop, True)}\n" + "\n".join(textwrap.wrap(
                    text, 47, break_long_words=False, break_on_hyphens=False
                ))
            )
        report.append(
            f"| {number} | {name} | {stamp(samples)} | {lead / RATE:.3f}s | "
            f"{tail / RATE:.3f}s | {stamp(cursor)}–{stamp(end)} |"
        )
        if i == demo_index:
            second_case = next(start for start, _, text in cues if text.startswith("Second case:"))
            demo = [
                "", "## Slide 6 terminal insert", "",
                f"- **{stamp(cursor)}** Show the original demo slide.",
                f"- **{stamp(speech_start)}** Switch to the `blindspot` terminal view.",
                f"- **{stamp(speech_start + second_case)}** Advance to `guard-attack`.",
                f"- **{stamp(speech_start + samples)}** Return to the original demo slide.",
                f"- **{stamp(end)}** Advance to Method.", "",
            ]
        cursor = end

    output = ROOT / "narration-preview.wav"
    sf.write(output, np.concatenate(preview), RATE, subtype="PCM_16")
    measured, _ = probe(output)
    if measured != cursor or measured >= LIMIT:
        raise ValueError("Combined audio failed the duration check")
    (ROOT / "captions.srt").write_text("\n\n".join(captions) + "\n", encoding="utf-8")
    (ROOT / "timing.md").write_text("\n".join(report + demo) + "\n", encoding="utf-8")
    print(f"Narration {stamp(speech)}, timed preview {stamp(measured)}, {len(captions)} captions")


def main():
    AUDIO.mkdir(exist_ok=True)
    import onnxruntime as ort

    options = ort.SessionOptions()
    options.intra_op_num_threads = 2
    options.inter_op_num_threads = 1
    models = ROOT / "models"
    session = ort.InferenceSession(str(models / "kokoro-v1.0.onnx"), sess_options=options,
                                   providers=["CPUExecutionProvider"])
    kokoro = Kokoro.from_session(session, str(models / "voices-v1.0.bin"))
    if VOICE not in kokoro.get_voices():
        raise ValueError(f"Requested voice is unavailable: {VOICE}")
    timeline([render(kokoro, *row) for row in slides()])


if __name__ == "__main__":
    main()
