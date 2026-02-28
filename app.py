from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session
from groq import Groq
import os

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import ListFlowable, ListItem
from reportlab.platypus import Preformatted
from reportlab.lib.pagesizes import letter
from reportlab.platypus import FrameBreak
from reportlab.platypus import KeepTogether
from reportlab.platypus import PageBreak
from reportlab.platypus import Table
from reportlab.platypus import TableStyle
from reportlab.platypus import HRFlowable
from reportlab.platypus import XPreformatted
from reportlab.platypus import Flowable
from reportlab.platypus import PageTemplate
from reportlab.platypus import BaseDocTemplate
from reportlab.platypus import Frame
from reportlab.platypus import NextPageTemplate
from reportlab.platypus import Indenter
from reportlab.platypus import DocAssign
from reportlab.platypus import DocExec
from reportlab.platypus import CondPageBreak
from reportlab.platypus import AnchorFlowable
from reportlab.platypus import Image
from reportlab.platypus import PageBreakIfNotEmpty
from reportlab.platypus import ParagraphAndImage
from reportlab.platypus import ListItem
from reportlab.platypus import PageBegin
from reportlab.platypus import TopPadder
from reportlab.platypus import FrameSplitter
from reportlab.platypus import BalancedColumns
from reportlab.platypus import NullDraw
from reportlab.platypus import KeepInFrame
from reportlab.platypus import CondPageBreak
from reportlab.platypus import NextPageTemplate
from reportlab.platypus import ImageAndFlowables
from reportlab.platypus import PageBreak
from reportlab.platypus import Macro
from reportlab.platypus import PageTemplate
from reportlab.platypus import Frame
from reportlab.platypus import Flowable
from reportlab.platypus import Spacer
from reportlab.platypus import Paragraph
from reportlab.platypus import SimpleDocTemplate
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Preformatted
from reportlab.lib.units import inch
from flask import send_file
import io

import PyPDF2

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB limit

import os

GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///studybuddy.db'

db = SQLAlchemy(app)
with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ---------------- User Model ----------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class StudySession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)  # will store full chat
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

# ---------------- Routes ----------------

# Landing Page
@app.route('/')
def index():
    return render_template("index.html")

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash("Username already exists")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please login.")
        return redirect(url_for('login'))

    return render_template("register.html")

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials")
            return redirect(url_for('login'))

    return render_template("login.html")


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():

    if "messages" not in session:
        session["messages"] = []

    if request.method == "POST":

        # -------- CHECK IF REGENERATE -------- #
        if request.form.get("regenerate") == "true":
            topic = session.get("last_topic")
            mode = session.get("last_mode")
        else:
            topic = request.form.get("topic")
            mode = request.form.get("mode")
            uploaded_file = request.files.get("pdf_file")

            # Save last values for regenerate
            session["last_topic"] = topic
            session["last_mode"] = mode

        # Safety check
        # If PDF uploaded
        if uploaded_file and uploaded_file.filename != "":
            reader = PyPDF2.PdfReader(uploaded_file)
            pdf_text = ""

            for page in reader.pages:
                pdf_text += page.extract_text() + "\n"

            topic = pdf_text[:3000]  # limit text to avoid overload
            mode = request.form.get("mode")

        else:
            topic = request.form.get("topic")
            mode = request.form.get("mode")

        # Save user message
            session["messages"].append({
            "role": "user",
            "content": topic
        })

        # -------- PROMPT BUILDING -------- #
        if mode == "summary":
            prompt = f"""
Summarize the following study material clearly:

{topic}
"""
        elif mode == "quiz":
            prompt = f"""
Generate 5 MCQs based on the following study material:

{topic}
"""

        elif mode == "flashcards":
            prompt = f"""
Generate 5 flashcards based on the following study material:

{topic}
"""

        else:
            prompt = f"Explain '{topic}'."

        # -------- GROQ CALL -------- #
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "user", "content": prompt}
            ],
        )

        ai_reply = response.choices[0].message.content

        # Save AI reply
        session["messages"].append({
            "role": "ai",
            "content": ai_reply
        })

        session.modified = True

    # Fetch sessions
    saved_sessions = StudySession.query.filter_by(
        user_id=current_user.id
    ).order_by(StudySession.created_at.desc()).all()

    return render_template(
        "dashboard.html",
        messages=session["messages"],
        saved_sessions=saved_sessions
    )

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/new')
@login_required
def new_study():

    messages = session.get("messages")

    if messages:
        full_chat = ""

        for msg in messages:
            role = msg["role"]
            content = msg["content"]
            full_chat += f"{role.upper()}: {content}\n\n"

        new_session = StudySession(
            user_id=current_user.id,
            title=messages[0]["content"][:50],  # first topic as title
            content=full_chat
        )

        db.session.add(new_session)
        db.session.commit()

    session.pop("messages", None)
    return redirect(url_for('dashboard'))

@app.route('/load/<int:session_id>')
@login_required
def load_session(session_id):

    study_session = StudySession.query.filter_by(
        id=session_id,
        user_id=current_user.id
    ).first()

    if not study_session:
        return redirect(url_for('dashboard'))

    # Convert saved text back into messages
    messages = []
    lines = study_session.content.split("\n\n")

    for line in lines:
        if line.startswith("USER:"):
            messages.append({
                "role": "user",
                "content": line.replace("USER: ", "")
            })
        elif line.startswith("AI:"):
            messages.append({
                "role": "ai",
                "content": line.replace("AI: ", "")
            })

    session["messages"] = messages
    session.modified = True

    return redirect(url_for('dashboard'))

@app.route("/delete_session/<int:session_id>", methods=["POST"])
@login_required
def delete_session(session_id):
    session_to_delete = StudySession.query.filter_by(
        id=session_id,
        user_id=current_user.id
    ).first()

    if session_to_delete:
        db.session.delete(session_to_delete)
        db.session.commit()

    return redirect(url_for("dashboard"))

@app.route("/export_pdf")
@login_required
def export_pdf():

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []

    styles = getSampleStyleSheet()
    normal_style = styles["Normal"]

    messages = session.get("messages", [])

    for msg in messages:
        role = msg["role"].upper()
        content = msg["content"]

        elements.append(Paragraph(f"<b>{role}</b>", styles["Heading4"]))
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph(content.replace("\n", "<br/>"), normal_style))
        elements.append(Spacer(1, 0.4 * inch))

    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="study_session.pdf",
        mimetype="application/pdf",
    )
# ---------------- Run ----------------

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)