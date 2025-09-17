# Video Tournament Application

## Overview
A Flask-based web application for hosting video tournaments where users can register, upload videos, vote on submissions, and view leaderboards. The application includes payment processing (currently in demo mode) for tournament entry fees.

## Recent Changes (September 17, 2025)
- **Environment Setup**: Configured for Replit with Python 3.11 and required dependencies
- **Security Improvements**: Added secure secret key generation, disabled debug mode in production, improved session security
- **Host Configuration**: Set Flask to bind to 0.0.0.0:5000 for Replit environment
- **Database**: SQLite database initialized with users, videos, votes, and comments tables
- **Workflow**: Configured to run Flask app on port 5000 with webview output
- **Deployment**: Set up autoscale deployment configuration with gunicorn

## Project Architecture
### Backend
- **Framework**: Flask web application
- **Database**: SQLite (tournament.db)
- **Server**: Flask dev server (development), gunicorn (production)
- **Port**: 5000 (frontend)

### Key Features
- User registration and authentication
- Video upload and management
- Voting system with ratings (1-5 stars)
- Comment system
- Leaderboard rankings
- Payment integration (Stripe - currently in demo mode)

### Security Notes
- **Payment Processing**: Currently in demo mode with mock payment flow. Production deployment requires proper Stripe webhook verification.
- **Secret Key**: Auto-generated secure key if FLASK_SECRET environment variable not set
- **Session Security**: HTTP-only cookies, SameSite protection
- **File Uploads**: Basic extension filtering, secure filename generation

## Environment Variables
- `FLASK_SECRET`: Application secret key (auto-generated if not set)
- `FLASK_DEBUG`: Set to 'true' to enable debug mode (default: false)
- `PORT`: Server port (default: 5000)
- `STRIPE_SECRET_KEY`: Stripe secret key (for payment processing)
- `STRIPE_PUBLISHABLE_KEY`: Stripe publishable key (for frontend)

## File Structure
```
/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── tournament.db         # SQLite database
├── static/
│   ├── uploads/          # User video uploads
│   └── thumbnails/       # Video thumbnails
└── templates/            # HTML templates
    ├── base.html
    ├── dashboard.html
    ├── leaderboard.html
    ├── login.html
    ├── payment.html
    ├── register.html
    ├── upload.html
    ├── video_detail.html
    └── videos.html
```

## User Preferences
- **Development Mode**: Flask development server with auto-reload
- **Production Mode**: Gunicorn WSGI server for deployment
- **Security**: Prioritize secure configurations over convenience features