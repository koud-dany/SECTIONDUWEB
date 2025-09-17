Video Tournament (fixed)
-----------------------

What's included:
- app.py (modified slightly to use a project-local sqlite DB and environment SECRET key)
- templates/ (individual template files extracted from the uploaded combined file)
- static/uploads/ (empty uploads folder to store user videos)
- requirements.txt

How to run (local development):
1. cd into the project folder:
   $ cd /workspace (or wherever you copied the files)
2. (optional) create and activate a Python virtualenv.
3. Install requirements:
   $ pip install -r requirements.txt
4. Export a secure secret key (recommended):
   $ export FLASK_SECRET='a-long-random-string'
5. Run the app:
   $ python app.py
   By default the app will create the sqlite DB at: /mnt/data/video_tournament_fixed/tournament.db

Notes and improvements made:
- Templates were split into separate files under templates/ (register.html, login.html, upload.html, videos.html, video_detail.html, leaderboard.html, payment.html, dashboard.html, base.html, index.html if present)
- app.py was updated to point to a local DB inside the project folder and to read a secret key from env `FLASK_SECRET`
- Created requirements.txt and README for quick start
- Static uploads folder ensured to exist

If you'd like, I can:
- Add Dockerfile / docker-compose
- Integrate Stripe frontend JS for real payments + webhooks
- Improve security (CSRF protection, input sanitization)
- Add unit tests and CI workflow
