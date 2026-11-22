"""Build the 1920x1080 AgentGuard-LLM draft from the 15 narration WAV files."""

import json
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import numpy as np
import soundfile as sf
from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
PREVIEW = PROJECT / ".venv" / "agentguard-recording.html"
AUDIO_DIR = ROOT / "slide-audio"
OUT_FRAMES = ROOT / "draft-frames"
RATE = 30
WIDTH = 1920
HEIGHT = 1080
LIMIT_SECONDS = 600
TARGET_SECONDS = 570


def run(command, capture=False):
    return subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        text=True,
    )


def stamp(seconds, srt=False):
    seconds = max(0, seconds)
    whole = int(seconds)
    milliseconds = round((seconds - whole) * 1000)
    if milliseconds == 1000:
        whole += 1
        milliseconds = 0
    h, rem = divmod(whole, 3600)
    m, s = divmod(rem, 60)
    if srt:
        return f"{h:02d}:{m:02d}:{s:02d},{milliseconds:03d}"
    return f"{m}:{s:02d}.{milliseconds:03d}"


def rows():
    text = (ROOT / "narration.md").read_text(encoding="utf-8-sig")
    parts = re.split(r"(?m)^## (\d+)\. ([\w-]+)[ \t]*$", text)
    result = []
    for number, name, body in zip(parts[1::3], parts[2::3], parts[3::3]):
        paragraphs = [p.strip() for p in re.split(r"\n\s*\n", body.strip())]
        spoken = " ".join(
            p for p in paragraphs if not p.startswith("**Production cue**")
        )
        result.append((int(number), name, " ".join(spoken.split())))
    slide_ids = re.findall(
        r'<section\b[^>]*\bid="([\w-]+)"',
        PREVIEW.read_text(encoding="utf-8"),
    )
    if len(result) != 15 or [r[1] for r in result] != slide_ids:
        raise RuntimeError("Master narration and recording preview are out of sync")
    return result


def canonicalize_audio():
    cover_duplicate = AUDIO_DIR / "01-sree ranj.wav"
    cover = AUDIO_DIR / "01-cover.wav"
    if cover_duplicate.exists():
        cover_duplicate.replace(cover)

    missing = []
    for number, name, _ in rows():
        path = AUDIO_DIR / f"{number:02d}-{name}.wav"
        if not path.exists():
            missing.append(path.name)
    if missing:
        raise RuntimeError("Missing slide WAV files: " + ", ".join(missing))


def chrome():
    candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    ]
    found = next((Path(p) for p in candidates if Path(p).exists()), None)
    if found is None:
        raise RuntimeError("Chrome or Edge is required to render the existing slide HTML")
    return str(found)


def render_slides():
    OUT_FRAMES.mkdir(exist_ok=True)
    html = PREVIEW.read_text(encoding="utf-8")
    html = html.replace(
        "fit();\nshow(0);",
        "fit();\nshow(Number(new URLSearchParams(location.search).get('slide') || '1') - 1);",
    )
    temp_html = ROOT / "draft-slides-temp.html"
    temp_html.write_text(html, encoding="utf-8")

    browser = chrome()
    for number, name, _ in rows():
        destination = OUT_FRAMES / f"{number:02d}-{name}.png"
        run([
            browser,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--hide-scrollbars",
            "--force-device-scale-factor=1",
            "--window-size=1920,1080",
            f"--screenshot={destination}",
            temp_html.as_uri() + f"?slide={number}",
        ])
    temp_html.unlink()


def wrap_text(text, font, draw, max_width):
    words = text.split()
    lines = []
    current = ""
    for word in words:
        trial = word if not current else current + " " + word
        if draw.textbbox((0, 0), trial, font=font)[2] <= max_width:
            current = trial
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def render_terminal(filename, title, output_text):
    image = Image.new("RGB", (WIDTH, HEIGHT), "#09111F")
    draw = ImageDraw.Draw(image)
    try:
        mono = ImageFont.truetype(r"C:\Windows\Fonts\consola.ttf", 21)
        bold = ImageFont.truetype(r"C:\Windows\Fonts\consolab.ttf", 24)
        label = ImageFont.truetype(r"C:\Windows\Fonts\segoeuib.ttf", 30)
    except OSError:
        mono = ImageFont.load_default()
        bold = mono
        label = mono

    draw.rectangle((0, 0, WIDTH, 82), fill="#132238")
    draw.text((44, 20), "OFFLINE REPLAY  ·  cached model responses", font=label, fill="#36C5B0")
    draw.text((1720, 28), title, font=bold, fill="#F2B84B")

    y = 108
    for line in output_text.splitlines():
        color = "#F3F0E8"
        if "→" in line or "→ " in line:
            color = "#F2B84B"
        elif "regex →" in line or "LLM guard →" in line:
            color = "#36C5B0"
        elif "ALLOW" in line:
            color = "#36C5B0"
        elif "BLOCK" in line:
            color = "#F0705A"
        if len(line) > 105:
            chunks = textwrap.wrap(line, 105)
        else:
            chunks = [line]
        for chunk in chunks:
            draw.text((44, y), chunk, font=mono, fill=color)
            y += 27
            if y > HEIGHT - 30:
                break
        if y > HEIGHT - 30:
            break
    path = OUT_FRAMES / filename
    image.save(path)


def render_terminal_assets():
    def read_capture(path):
        data = path.read_bytes()
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return data.decode("utf-16")
        return data.decode("utf-8-sig")

    blindspot = read_capture(ROOT / "blindspot-offline.txt")
    guard = read_capture(ROOT / "guard-attack-offline.txt")
    render_terminal("blindspot-offline.png", "blindspot", blindspot)
    render_terminal("guard-attack-offline.png", "guard-attack", guard)


def frame_count(seconds):
    return max(1, round(seconds * RATE))


def ffmpeg_image_clip(image, duration_frames, output):
    run([
        "ffmpeg", "-y", "-v", "error",
        "-loop", "1", "-i", str(image),
        "-frames:v", str(duration_frames),
        "-r", str(RATE),
        "-vf", f"scale={WIDTH}:{HEIGHT}:flags=lanczos",
        "-c:v", "libx264", "-pix_fmt", "yuv420p",
        "-an", str(output),
    ])


def build_timeline(row_info):
    durations = []
    for number, name, _ in row_info:
        path = AUDIO_DIR / f"{number:02d}-{name}.wav"
        durations.append(float(sf.info(path).duration))

    total_speech = sum(durations)
    leads = [0.5] * len(row_info)
    tails = [2.024] * len(row_info)
    demo = next(i for i, (_, name, _) in enumerate(row_info) if name == "demo")
    leads[demo] = 4.0
    tails[demo] = max(13.626, 55.0 - leads[demo] - durations[demo])

    minimum = total_speech + sum(leads) + sum(tails)
    if minimum >= LIMIT_SECONDS:
        raise RuntimeError(
            f"Narration timeline would be {minimum:.3f}s, not strictly below 10:00"
        )

    slack = max(0.0, TARGET_SECONDS - minimum)
    other = [i for i in range(len(row_info)) if i != demo]
    base = slack / len(other)
    fractional = slack - base * len(other)
    for i in other:
        tails[i] += base

    total = total_speech + sum(leads) + sum(tails)
    if total >= LIMIT_SECONDS:
        raise RuntimeError(
            f"Final timeline would be {total:.3f}s, not strictly below 10:00"
        )

    cursor = 0.0
    timeline = []
    for i, (number, name, text) in enumerate(row_info):
        slot = leads[i] + durations[i] + tails[i]
        timeline.append({
            "number": number,
            "name": name,
            "text": text,
            "audio": durations[i],
            "lead": leads[i],
            "tail": tails[i],
            "slot": slot,
            "start": cursor,
            "speech_start": cursor + leads[i],
            "end": cursor + slot,
        })
        cursor += slot
    return timeline, total


def build_combined_audio(timeline):
    combined = []
    for item in timeline:
        combined.append(np.zeros(frame_count(item["lead"]) * 800, dtype=np.float32))
        audio, rate = sf.read(
            AUDIO_DIR / f"{item['number']:02d}-{item['name']}.wav",
            dtype="float32",
        )
        if rate != 24000:
            raise RuntimeError("Slide WAV files must use 24 kHz")
        if audio.ndim > 1:
            audio = audio.mean(axis=1)
        combined.append(audio)
        combined.append(np.zeros(frame_count(item["tail"]) * 800, dtype=np.float32))
    output = ROOT / "narration-preview.wav"
    sf.write(output, np.concatenate(combined), 24000, subtype="PCM_16")
    return output


def build_video_segments(timeline):
    segment_dir = OUT_FRAMES / "segments"
    segment_dir.mkdir(exist_ok=True)
    concat = []
    for item in timeline:
        number = item["number"]
        name = item["name"]
        if name == "demo":
            blind = OUT_FRAMES / "blindspot-offline.png"
            guard = OUT_FRAMES / "guard-attack-offline.png"
            lead_frames = frame_count(item["lead"])
            speech_frames = frame_count(item["audio"])
            guard_at = lead_frames + round(0.548 * speech_frames)
            tail_start = lead_frames + speech_frames
            blind_frames = guard_at - lead_frames
            guard_frames = tail_start - guard_at
            demo_tail_frames = frame_count(item["slot"]) - tail_start

            parts = [
                (OUT_FRAMES / f"{number:02d}-{name}.png", lead_frames),
                (blind, blind_frames),
                (guard, guard_frames),
                (OUT_FRAMES / f"{number:02d}-{name}.png", demo_tail_frames),
            ]
            for index, (image, frames) in enumerate(parts):
                output = segment_dir / f"{number:02d}-demo-{index}.mp4"
                ffmpeg_image_clip(image, frames, output)
                concat.append(output)
        else:
            image = OUT_FRAMES / f"{number:02d}-{name}.png"
            output = segment_dir / f"{number:02d}-{name}.mp4"
            ffmpeg_image_clip(image, frame_count(item["slot"]), output)
            concat.append(output)

    concat_file = segment_dir / "concat.txt"
    concat_file.write_text(
        "".join(f"file '{path.as_posix()}'\n" for path in concat),
        encoding="utf-8",
    )
    return concat_file


def concat_visual(concat_file):
    output = OUT_FRAMES / "draft-visual.mp4"
    run([
        "ffmpeg", "-y", "-v", "error",
        "-f", "concat", "-safe", "0", "-i", str(concat_file),
        "-c", "copy", str(output),
    ])
    return output


def mux_video(visual, audio):
    clean = ROOT / "agentguard-draft.mp4"
    run([
        "ffmpeg", "-y", "-v", "error",
        "-i", str(visual),
        "-i", str(audio),
        "-map", "0:v:0", "-map", "1:a:0",
        "-c:v", "libx264", "-pix_fmt", "yuv420p",
        "-r", str(RATE),
        "-c:a", "aac", "-b:a", "192k",
        "-shortest", str(clean),
    ])
    return clean


def write_captions(timeline):
    entries = []
    counter = 1
    for item in timeline:
        sentences = re.split(r"(?<=[.!?])\s+", item["text"])
        sentences = [s.strip() for s in sentences if s.strip()]
        weights = [max(1, len(s)) for s in sentences]
        cursor = item["speech_start"]
        for index, sentence in enumerate(sentences):
            duration = item["audio"] * weights[index] / sum(weights)
            end = cursor + duration
            entries.append(
                f"{counter}\n{stamp(cursor, True)} --> {stamp(end, True)}\n"
                + "\n".join(textwrap.wrap(sentence, 47, break_long_words=False,
                                          break_on_hyphens=False))
            )
            cursor = end
            counter += 1
    path = ROOT / "captions.srt"
    path.write_text("\n\n".join(entries) + "\n", encoding="utf-8")
    return path


def build_captioned(clean, srt):
    output = ROOT / "agentguard-draft-captioned.mp4"
    run([
        "ffmpeg", "-y", "-v", "error",
        "-i", str(clean),
        "-i", str(srt),
        "-map", "0", "-map", "1",
        "-c", "copy",
        "-c:s", "mov_text",
        str(output),
    ])
    return output


def write_timing(timeline, total):
    report = [
        "# Measured narration and video timing",
        "",
        "- Voice: Kokoro `am_michael` at 1.0x for the current draft.",
        f"- Total measured slide narration: **{stamp(sum(i['audio'] for i in timeline))}**.",
        f"- Final generated timeline: **{stamp(total)}**.",
        "- Strict limit: below 10:00.",
        "- Slide 6 uses genuine offline replay output for both scenarios.",
        "- Captions are regenerated from the master narration and measured audio durations.",
        "",
        "| Slide | Topic | WAV duration | Lead hold | End hold | Video timeline |",
        "|---:|---|---:|---:|---:|---|",
    ]
    for item in timeline:
        report.append(
            f"| {item['number']} | {item['name']} | "
            f"{stamp(item['audio'])} | {item['lead']:.3f}s | "
            f"{item['tail']:.3f}s | {stamp(item['start'])}-{stamp(item['end'])} |"
        )
    report.extend([
        "",
        "## Slide 6 offline terminal insert",
        "",
        f"- Blindspot replay starts at {stamp(timeline[5]['speech_start'] + 4)}.",
        f"- Guard-attack replay starts proportionally after the blindspot hold.",
        f"- The original demo slide returns before slide 7.",
        "",
    ])
    (ROOT / "timing.md").write_text("\n".join(report), encoding="utf-8")


def ffprobe(path):
    result = run([
        "ffprobe", "-v", "error",
        "-show_entries",
        "format=duration:stream=index,codec_type,width,height,avg_frame_rate,r_frame_rate",
        "-of", "json", str(path),
    ], capture=True)
    print(result.stdout)


def main():
    canonicalize_audio()
    row_info = rows()
    render_slides()
    render_terminal_assets()
    timeline, total = build_timeline(row_info)
    audio = build_combined_audio(timeline)
    concat = build_video_segments(timeline)
    visual = concat_visual(concat)
    clean = mux_video(visual, audio)
    srt = write_captions(timeline)
    captioned = build_captioned(clean, srt)
    write_timing(timeline, total)

    print(f"CLEAN={clean}")
    print(f"CAPTIONED={captioned}")
    print(f"SUBTITLES={srt}")
    print(f"TIMING={ROOT / 'timing.md'}")
    print("FFPROBE clean draft:")
    ffprobe(clean)
    print("FFPROBE captioned draft:")
    ffprobe(captioned)


if __name__ == "__main__":
    main()
