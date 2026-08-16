ADAPTIVE CERTIFICATION COMMAND CENTER

Replace these files in your project:

1. app.py
2. database.py
3. templates/index.html
4. static/style.css

Then run:

cd D:\Projects\cissp-command-center
.\.venv\Scripts\Activate.ps1
python database.py
python app.py

Open:
http://127.0.0.1:5001

Then hard refresh:
Ctrl+Shift+R

WHAT CHANGED
- Campaign cards remain on the fixed CISM -> CISSP roadmap.
- Each card now carries a DATA DRIVEN prescription based on current scores and evidence volume.
- The top priority banner is also data driven.
- CISM historical February results only influence recommendations while current evidence is thin.
- Current red/yellow performance overrides historical results.
- Green domains with low sample size are told to build evidence instead of being treated as weak.
- Ready domains shift the prescription toward mixed testing / mock exams.
- Campaign card modals show a LIVE PRESCRIPTION section before the static phase strategy.
