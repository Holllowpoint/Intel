# Intel Study Planner

Intel is a Python desktop application that helps students and teachers plan
syllabus work. Students can track topics, assignments, and deadlines; teachers
can build and share syllabus items. An optional AI companion analyses the
syllabus and suggests next steps.

Built with Tkinter. No web server or database service is required.

## Features

- **Two workspaces** — separate student and teacher flows.
- **Syllabus tracking** — add, view, update, and delete syllabus items with
  subject, type, date, and time.
- **Natural-language dates** — type `tomorrow`, `in 2 weeks`, `mon`, or
  `next friday` and Intel converts it to a date.
- **Calendar export** — export the syllabus to `.ics` so it opens in any
  calendar app.
- **CSV export** — export syllabus items for spreadsheets or backup.
- **AI companion** — optional Gemini or OpenAI integration that reads the
  syllabus and returns structured recommendations.
- **Offline mode** — the prototype answers locally when no API key is set.

## Requirements

- Python 3.10 or newer

## Installation

```bash
git clone https://github.com/Holllowpoint/Intel.git
cd Intel
python -m pip install -r requirements.txt
```

## Running

Start the full application:

```bash
python Intelli.py
```

Start the offline learning prototype (no API key or internet needed):

```bash
python app.py
```

## Configuration

The AI companion is optional. Without a key the app runs offline.

Set a Gemini key for the current PowerShell session:

```powershell
$env:GEMINI_API_KEY = "your-key-here"
```

Or set an OpenAI key to use the OpenAI backend:

```powershell
$env:OPENAI_API_KEY = "your-key-here"
```

Never commit real keys. Intel reads them from the environment at runtime.

## Running the tests

```bash
python -m unittest discover -s tests
```

## Project structure

```
.
├── Intelli.py            # Full application: UI, workspaces, syllabus, AI
├── app.py                # Offline prototype used for learning
├── auth.py               # Password hashing and verification
├── database.py           # SQLite storage for users and syllabus items
├── gemini_companion.py   # Optional Gemini API integration
├── tests/                # Unit tests
├── requirements.txt      # Python dependencies
└── README.md
```

### Module notes

- `Intelli.py` — Tkinter UI and application flow. This is the main entry point.
- `app.py` — deliberately simple prototype. It exists to practise the interface
  before Gemini, accounts, and a database are added.
- `auth.py` — PBKDF2 password hashing with random salts.
- `database.py` — `SyllabusDB` handles users and syllabus items.
- `gemini_companion.py` — requests-based Gemini client with retry and backoff.

## Database

Intel creates `syllabus.db` beside the Python files on first run. The database
is local to your machine and is git-ignored. Delete it to start fresh.

## License

MIT — see [LICENSE](LICENSE).
