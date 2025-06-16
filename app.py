from flask import Flask, render_template, url_for, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os
import pdfplumber
import spacy
import re
from collections import Counter
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import json

# Download NLTK stopwords if not already downloaded
try:
    stopwords.words('english')
    word_tokenize("test") # Check for punkt as well
except LookupError:
    import nltk
    nltk.download('stopwords')
    nltk.download('punkt')


app = Flask(__name__)

bcrypt = Bcrypt(app)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SECRET_KEY'] = 'thisisasecretkey'

# Folder to store uploads
UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Load SpaCy model
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    print("SpaCy model 'en_core_web_sm' not found. Please run: python -m spacy download en_core_web_sm")
    exit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError('That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

class UploadForm(FlaskForm):
    # No direct file input here as we handle it with request.files in dashboard
    jd = TextAreaField('Job Description', validators=[InputRequired()], render_kw={"placeholder": "Paste the job description here...", "rows": 10, "cols": 50})
    submit = SubmitField('Submit')

def extract_text_from_pdf(pdf_path):
    text = ""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                text += page.extract_text() + "\n"
    except Exception as e:
        print(f"Error extracting text from PDF: {e}")
        return None
    return text

def parse_resume(text):
    doc = nlp(text)

    # Extracting names (basic approach)
    name = ""
    for ent in doc.ents:
        if ent.label_ == "PERSON":
            name = ent.text
            break # Assuming the first person is the name

    # Extracting emails (regex)
    email = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
    email = email[0] if email else "N/A"

    # Extracting phone numbers (regex)
    phone = re.findall(r"(\+?\d{1,3}[-\.\s]?)?(\(?\d{3}\)?[-\.\s]?)?(\d{3}[-\.\s]?\d{4})", text)
    # This regex is a bit complex for simple concatenation. Let's simplify and make it more robust.
    # For US/Canada format (XXX) XXX-XXXX or XXX-XXX-XXXX
    phone_match = re.search(r'(\+?\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}', text)
    phone = phone_match.group(0) if phone_match else "N/A"

    # Extracting education (simple keyword search, can be improved)
    education_keywords = ["education", "university", "college", "degree", "bachelor", "master", "phd", "B.Tech", "M.Tech"]
    education_section = []
    # A more sophisticated approach would be to extract sentences/paragraphs around these keywords
    # For demonstration, we'll try to get lines containing these keywords
    lines = text.split('\n')
    for line in lines:
        if any(keyword.lower() in line.lower() for keyword in education_keywords):
            education_section.append(line.strip())
            # break # Remove break to capture all relevant lines

    # Extracting experience (simple keyword search)
    experience_keywords = ["experience", "work history", "employment", "project", "projects", "internship"]
    experience_section = []
    for line in lines:
        if any(keyword.lower() in line.lower() for keyword in experience_keywords):
            experience_section.append(line.strip())
            # break # Remove break to capture all relevant lines


    # For a full-fledged parser, you would use more advanced NLP techniques
    # like dependency parsing, entity recognition models trained on resume data, etc.

    return {
        "name": name,
        "email": email,
        "phone": phone,
        "education": education_section if education_section else ["N/A"],
        "experience": experience_section if experience_section else ["N/A"],
        "raw_text": text # Keep raw text for skill extraction
    }

def extract_skills(text):
    # Expanded list of common tech skills and some soft skills
    common_skills = [
        "python", "java", "c++", "c#", "javascript", "html", "css", "react", "angular",
        "vue.js", "node.js", "sql", "mysql", "postgresql", "mongodb", "aws", "azure", "gcp",
        "docker", "kubernetes", "git", "linux", "unix", "windows", "agile", "scrum", "kanban",
        "tensorflow", "pytorch", "machine learning", "data science", "nlp", "artificial intelligence",
        "tableau", "power bi", "excel", "google sheets", "rest api", "api", "microservices",
        "spring boot", "django", "flask", "ruby on rails", "php", "laravel", "swift", "kotlin",
        "android", "ios", "devops", "ci/cd", "jenkins", "gitlab ci", "aws ec2", "s3", "lambda",
        "azure functions", "google cloud functions", "big data", "hadoop", "spark", "kafka",
        "communication", "teamwork", "problem-solving", "leadership", "project management",
        "analytical thinking", "critical thinking", "creativity", "adaptability", "attention to detail",
        "customer service", "sales", "marketing", "financial analysis", "budgeting",
        "data analysis", "statistical analysis", "web development", "mobile development", "software development",
        "testing", "qa", "cybersecurity", "network security", "cloud computing", "microsoft office", "google workspace",
        "data structures", "algorithms", "object-oriented programming", "oop", "frontend", "backend",
        "full stack", "ux/ui", "design", "autocad", "matlab", "r", "sas", "spss"
    ]

    found_skills = []
    text_lower = text.lower()
    
    # Tokenize and remove stopwords for better matching
    words = word_tokenize(text_lower)
    # Using a set for stop_words lookup is faster
    stop_words_set = set(stopwords.words('english'))
    filtered_words = [word for word in words if word.isalnum() and word not in stop_words_set]
    filtered_text = ' '.join(filtered_words) # Join back for multi-word skill matching

    # Match single and multi-word skills from predefined list
    for skill in common_skills:
        if skill.lower() in filtered_text:
            found_skills.append(skill.capitalize()) # Capitalize for consistent display

    # Use SpaCy's entity recognition for potential skills (often picks up organizations, products, etc.)
    doc = nlp(text)
    for ent in doc.ents:
        # Consider specific entity types that might represent skills/technologies
        # This list can be refined based on what SpaCy models typically tag well
        if ent.label_ in ["ORG", "PRODUCT", "LANGUAGE", "NORP", "GPE"]: # NORP for nationalities/religious/political groups, GPE for geopolitical entities, often pick up tech companies/frameworks. Be careful with these.
            # Avoid adding very short or common words that aren't skills
            if len(ent.text) > 2 and ent.text.lower() not in stop_words_set:
                if ent.text.lower() not in [s.lower() for s in found_skills]: # Avoid duplicates
                    found_skills.append(ent.text)
    
    # Deduplicate and return
    return sorted(list(set(found_skills))) # Sort for consistent order

def compare_skills_and_score(resume_skills, jd_skills):
    resume_set = set(skill.lower() for skill in resume_skills)
    jd_set = set(skill.lower() for skill in jd_skills)

    matched_skills = sorted(list(resume_set.intersection(jd_set)))
    missing_skills = sorted(list(jd_set.difference(resume_set)))
    extra_skills = sorted(list(resume_set.difference(jd_set)))

    # Calculate ATS Score
    if len(jd_set) == 0:
        ats_score = 0 # Or 100 if no JD skills are expected, depends on interpretation
        if len(resume_set) > 0: # If resume has skills but JD has none
            ats_score = 50 # Arbitrary score for some resume skills, no JD comparison
    else:
        ats_score = (len(matched_skills) / len(jd_set)) * 100
    ats_score = round(ats_score, 2) # Round to 2 decimal places

    # Determine Resume Strength
    strength = "Weak"
    if ats_score >= 80:
        strength = "Excellent"
    elif ats_score >= 60:
        strength = "Good"
    elif ats_score >= 30:
        strength = "Average"

    # Generate Overall Feedback
    feedback = "Based on the comparison, here are some recommendations:\n\n"
    if ats_score < 30:
        feedback += "- Your resume seems to have very few matching skills with the job description. Consider tailoring your resume more closely to the job requirements.\n"
    elif ats_score < 60:
        feedback += "- You have some matching skills, but there's room for improvement. Focus on highlighting skills directly relevant to the job description.\n"
    else:
        feedback += "- Your resume shows a strong match with the job description! Well done.\n"

    if missing_skills:
        feedback += f"- Consider adding or emphasizing the following crucial skills from the job description in your resume: {', '.join(missing_skills)}.\n"
    if extra_skills:
        feedback += f"- You have listed skills not explicitly mentioned in the job description: {', '.join(extra_skills)}. While these might be valuable, ensure they don't overshadow the core requirements.\n"
    
    if len(jd_set) == 0:
        feedback += "- No specific skills were extracted from the job description. Please ensure the job description contains clear technical keywords for better analysis."
    
    return {
        "ats_score": ats_score,
        "strength": strength,
        "matched_skills": matched_skills,
        "missing_skills": missing_skills,
        "extra_skills": extra_skills,
        "feedback": feedback
    }


def suggest_courses_and_videos(skills):
    # This is a placeholder function. In a real application, you would:
    # 1. Have a database of courses/videos linked to skills.
    # 2. Use a recommendation engine.
    # 3. Integrate with APIs from learning platforms (e.g., Coursera, Udemy, YouTube).

    suggestions = {}
    for skill in skills:
        skill_lower = skill.lower()
        if "python" in skill_lower:
            suggestions[skill] = [
                {"title": "Python for Everybody (Coursera)", "url": "https://www.coursera.org/specializations/python"},
                {"title": "Corey Schafer Python Tutorials (YouTube)", "url": "https://www.youtube.com/playlist?list=PL-osiEwhsQmC9--K_f6wM-Vr-d2fthgxC"} # Updated link
            ]
        elif "javascript" in skill_lower or "react" in skill_lower or "node.js" in skill_lower:
            suggestions[skill] = [
                {"title": "The Complete JavaScript Course (Udemy)", "url": "https://www.udemy.com/course/the-complete-javascript-course/"},
                {"title": "Academind React.js Course (YouTube)", "url": "https://www.youtube.com/playlist?list=PL55RiY5tL51rz0EamN2q3_M5j7jY2dM_D"} # Updated link
            ]
        elif "machine learning" in skill_lower or "data science" in skill_lower:
             suggestions[skill] = [
                {"title": "Machine Learning by Andrew Ng (Coursera)", "url": "https://www.coursera.org/learn/machine-learning"},
                {"title": "StatQuest with Josh Starmer (YouTube)", "url": "https://www.youtube.com/@StatQuest"} # Updated link
            ]
        elif "sql" in skill_lower:
             suggestions[skill] = [
                {"title": "SQL for Data Science (Coursera)", "url": "https://www.coursera.org/learn/sql-for-data-science"},
                {"title": "FreeCodeCamp SQL Tutorials (YouTube)", "url": "https://www.youtube.com/playlist?list=PLWKjhJtqVunFX52q3Y-2mYlDFG0_QxR6M"} # Updated link
            ]
        else:
            suggestions[skill] = [
                {"title": f"Search for {skill} tutorials on YouTube", "url": f"https://www.youtube.com/results?search_query={skill.replace(' ', '+')}+tutorial"}, # Corrected Youtube URL
                {"title": f"Search for {skill} courses on Coursera", "url": f"https://www.coursera.org/search?query={skill.replace(' ', '%20')}"}
            ]
    return suggestions


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger') # Flash message for invalid credentials
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UploadForm() # Use the UploadForm for JD
    if request.method == 'POST':
        resume_file = request.files.get('resume')
        jd_text = form.jd.data # Get JD from form

        if not resume_file or not jd_text:
            flash("Please upload a resume and paste the job description.", "danger")
            return redirect(url_for('dashboard'))

        if resume_file.filename == '':
            flash("No selected file for resume.", "danger")
            return redirect(url_for('dashboard'))

        if resume_file and allowed_file(resume_file.filename):
            filename = secure_filename(resume_file.filename)
            resume_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            resume_file.save(resume_path)

            flash("Resume uploaded successfully!", "success")

            # 3) PDF Extraction
            resume_text = extract_text_from_pdf(resume_path)
            if not resume_text:
                flash("Could not extract text from the resume PDF. Please ensure it's a valid PDF.", "danger")
                return redirect(url_for('dashboard'))

            # 4) Resume Parsing (Basic Info)
            parsed_resume_data = parse_resume(resume_text)
            
            # 5) Extract Skills
            extracted_skills = extract_skills(parsed_resume_data['raw_text']) # Use raw text for skill extraction
            jd_skills = extract_skills(jd_text) # Extract skills from JD

            # 6) Compare Skills and Calculate ATS Score
            comparison_results = compare_skills_and_score(extracted_skills, jd_skills)

            # 7) Suggest Courses and Videos (based on ALL extracted skills, or missing skills, depending on desired logic)
            # For this example, we'll suggest based on all skills found in the resume
            suggested_resources = suggest_courses_and_videos(extracted_skills)

            # Now, pass all this data to a results template
            return render_template(
                'results.html',
                resume_data=parsed_resume_data,
                extracted_resume_skills=extracted_skills, # Renamed for clarity
                jd_text=jd_text,
                jd_skills=jd_skills,
                suggested_resources=suggested_resources,
                # New comparison data:
                ats_score=comparison_results['ats_score'],
                resume_strength=comparison_results['strength'],
                matched_skills=comparison_results['matched_skills'],
                missing_skills=comparison_results['missing_skills'],
                extra_skills=comparison_results['extra_skills'],
                overall_feedback=comparison_results['feedback']
            )
        else:
            flash("Invalid file type for resume. Only PDF is allowed.", "danger")
            return redirect(url_for('dashboard'))

    return render_template('dashboard.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'pdf'} # Only allow PDF for now

# Create database
with app.app_context():
    db.create_all()
    print("✅ Tables created!")
    print("📂 Database path:", os.path.abspath("database.db"))

if __name__ == "__main__":
    app.run(debug=True)