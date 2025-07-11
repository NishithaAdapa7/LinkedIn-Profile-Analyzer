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

# Download NLTK resources if not already downloaded
def setup_nltk():
    import nltk
    required_resources = ['stopwords', 'punkt', 'punkt_tab']
    
    for resource in required_resources:
        try:
            nltk.data.find(f'tokenizers/{resource}')
        except LookupError:
            try:
                print(f"Downloading {resource}...")
                nltk.download(resource, quiet=True)
            except Exception as e:
                print(f"Could not download {resource}: {e}")
    
    # Test if everything works
    try:
        stopwords.words('english')
        word_tokenize("test")
        print("✅ NLTK setup complete!")
    except Exception as e:
        print(f"❌ NLTK setup failed: {e}")

# Call the setup function
setup_nltk()


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
def extract_name_from_lines(lines):
    for line in lines:
        stripped_line = line.strip()
        # Check if line has exactly 2 words and is likely a name (all alphabetic)
        if len(stripped_line.split()) == 2 and all(word.isalpha() for word in stripped_line.split()):
            return stripped_line.title()  # Title-case the name (e.g., "Mansi Mehta")
    return "N/A"

    

def parse_resume(text):
    doc = nlp(text)

    # Extracting names (improved approach)
    lines = text.splitlines()
    # Use layout-based name extraction
    name = extract_name_from_lines(lines)
    for ent in doc.ents:
        if ent.label_ == "PERSON":
            name = ent.text
            break
    # Fallback: use first non-empty line if SpaCy fails
    if not name:
        for line in text.splitlines():
            line = line.strip()
            if line and line.replace(' ', '').isalpha() and line[0].isupper():
                name = line
                break

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

    # Add exclusion list for locations, names, and irrelevant terms
    exclusion_list = [
        "andhra pradesh", "telangana", "hyderabad", "bangalore", "chennai", "mumbai", "delhi",
        "india", "usa", "united states", "canada", "uk", "united kingdom", "australia",
        "tamil nadu", "karnataka", "kerala", "maharashtra", "gujarat", "rajasthan",
        "national institute of technology", "iit", "nit", "indian institute of technology",
        "university", "college", "institute", "school", "ltd", "pvt", "private", "limited",
        "company", "corporation", "inc", "technologies", "solutions", "systems", "services",
        "infosys", "tcs", "wipro", "cognizant", "accenture", "capgemini", "hcl", "tech mahindra"
    ]

    found_skills = []
    text_lower = text.lower()
    
    # Tokenize and remove stopwords for better matching
    words = word_tokenize(text_lower)
    stop_words_set = set(stopwords.words('english'))
    filtered_words = [word for word in words if word.isalnum() and word not in stop_words_set]
    filtered_text = ' '.join(filtered_words)

    # Match single and multi-word skills from predefined list
    for skill in common_skills:
        if skill.lower() in filtered_text:
            found_skills.append(skill.capitalize())

    # Use SpaCy's entity recognition with better filtering
    doc = nlp(text)
    for ent in doc.ents:
        # Only consider certain entity types and apply strict filtering
        if ent.label_ in ["ORG", "PRODUCT"]:  # Removed GPE and NORP to avoid locations
            entity_text = ent.text.lower().strip()
            
            # Skip if it's in exclusion list
            if any(excluded.lower() in entity_text for excluded in exclusion_list):
                continue
                
            # Skip very short terms or common words
            if len(entity_text) <= 2 or entity_text in stop_words_set:
                continue
                
            # Skip if it contains numbers (likely dates, versions, etc.)
            if any(char.isdigit() for char in entity_text):
                continue
                
            # Skip if it looks like a company name (contains common suffixes)
            company_suffixes = ["ltd", "inc", "corp", "llc", "pvt", "limited", "technologies", "solutions"]
            if any(suffix in entity_text for suffix in company_suffixes):
                continue
                
            # Only add if it's not already in the list (case-insensitive)
            if entity_text not in [s.lower() for s in found_skills]:
                found_skills.append(ent.text.title())
    
    # Additional filtering: remove skills that are likely locations or person names
    filtered_skills = []
    for skill in found_skills:
        skill_lower = skill.lower()
        # Skip if it's clearly a location or person name
        if not any(excluded.lower() in skill_lower for excluded in exclusion_list):
            filtered_skills.append(skill)
    
    # Deduplicate and return
    return sorted(list(set(filtered_skills)))

def compare_skills_and_score(resume_skills, jd_skills, resume_text="", jd_text=""):
    resume_set = set(skill.lower() for skill in resume_skills)
    jd_set = set(skill.lower() for skill in jd_skills)

    matched_skills = sorted(list(resume_set.intersection(jd_set)))
    missing_skills = sorted(list(jd_set.difference(resume_set)))
    extra_skills = sorted(list(resume_set.difference(jd_set)))

    # Enhanced ATS Score Calculation with multiple factors
    skill_match_score = 0
    keyword_density_score = 0
    format_score = 0
    experience_relevance_score = 0
    
    # 1. Skills Matching Score (40% weight)
    if len(jd_set) > 0:
        skill_match_score = (len(matched_skills) / len(jd_set)) * 100
    else:
        skill_match_score = 50 if len(resume_set) > 0 else 0
    
    # 2. Keyword Density Score (25% weight)
    if jd_text and resume_text:
        jd_keywords = set(word.lower() for word in word_tokenize(jd_text) 
                         if word.isalnum() and len(word) > 3)
        resume_keywords = set(word.lower() for word in word_tokenize(resume_text) 
                            if word.isalnum() and len(word) > 3)
        
        common_keywords = jd_keywords.intersection(resume_keywords)
        if len(jd_keywords) > 0:
            keyword_density_score = (len(common_keywords) / len(jd_keywords)) * 100
        else:
            keyword_density_score = 50
    else:
        skill_match_score = 50 if len(resume_set) > 0 else 0
    
    # 2. Keyword Density Score (25% weight)
    if jd_text and resume_text:
        jd_keywords = set(word.lower() for word in word_tokenize(jd_text) 
                         if word.isalnum() and len(word) > 3)
        resume_keywords = set(word.lower() for word in word_tokenize(resume_text) 
                            if word.isalnum() and len(word) > 3)
        
        common_keywords = jd_keywords.intersection(resume_keywords)
        if len(jd_keywords) > 0:
            keyword_density_score = (len(common_keywords) / len(jd_keywords)) * 100
        else:
            keyword_density_score = 50
    else:
        keyword_density_score = 50
    
    # 3. Format Score (20% weight) - Basic ATS-friendly format checks
    format_score = calculate_format_score(resume_text)
    
    # 4. Experience Relevance Score (15% weight)
    experience_relevance_score = calculate_experience_relevance(resume_text, jd_text)
    
    # Calculate weighted ATS score
    ats_score = (
        skill_match_score * 0.40 +
        keyword_density_score * 0.25 +
        format_score * 0.20 +
        experience_relevance_score * 0.15
    )
    
    ats_score = round(ats_score, 2)

    # Enhanced strength assessment
    strength = "Weak"
    if ats_score >= 85:
        strength = "Excellent"
    elif ats_score >= 70:
        strength = "Good"
    elif ats_score >= 50:
        strength = "Average"

    # Enhanced feedback with detailed breakdown
    feedback = generate_detailed_feedback(
        ats_score, skill_match_score, keyword_density_score, 
        format_score, experience_relevance_score, 
        matched_skills, missing_skills, extra_skills
    )
    
    return {
        "ats_score": ats_score,
        "strength": strength,
        "matched_skills": matched_skills,
        "missing_skills": missing_skills,
        "extra_skills": extra_skills,
        "feedback": feedback,
        "score_breakdown": {
            "skill_match": round(skill_match_score, 2),
            "keyword_density": round(keyword_density_score, 2),
            "format_score": round(format_score, 2),
            "experience_relevance": round(experience_relevance_score, 2)
        }
    }

def calculate_format_score(resume_text):
    """Calculate ATS-friendly format score"""
    score = 100
    
    # Check for ATS-unfriendly elements
    if len(re.findall(r'[│┌┐└┘├┤┬┴┼]', resume_text)) > 0:
        score -= 15  # Tables/graphics characters
    
    if len(re.findall(r'[@#$%^&*()_+=\[\]{}|\\:";\'<>?,./]', resume_text)) > len(resume_text) * 0.05:
        score -= 10  # Too many special characters
    
    # Check for contact info presence
    if not re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resume_text):
        score -= 20  # No email found
    
    if not re.search(r'(\+?\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}', resume_text):
        score -= 15  # No phone found
    
    # Check for standard sections
    sections = ['education', 'experience', 'skills', 'work', 'employment']
    found_sections = sum(1 for section in sections if section.lower() in resume_text.lower())
    if found_sections < 3:
        score -= 20
    
    return max(0, score)

def calculate_experience_relevance(resume_text, jd_text):
    """Calculate experience relevance score"""
    if not jd_text or not resume_text:
        return 50
    
    # Extract years of experience mentioned
    jd_years = re.findall(r'(\d+)\+?\s*years?\s+(?:of\s+)?experience', jd_text.lower())
    resume_years = re.findall(r'(\d+)\+?\s*years?\s+(?:of\s+)?experience', resume_text.lower())
    
    score = 70  # Base score
    
    if jd_years and resume_years:
        required_years = max([int(year) for year in jd_years])
        candidate_years = max([int(year) for year in resume_years])
        
        if candidate_years >= required_years:
            score = 90
        elif candidate_years >= required_years * 0.8:
            score = 75
        else:
            score = 50
    
    # Check for relevant job titles/roles
    common_roles = ['developer', 'engineer', 'analyst', 'manager', 'specialist', 'consultant']
    jd_roles = [role for role in common_roles if role in jd_text.lower()]
    resume_roles = [role for role in common_roles if role in resume_text.lower()]
    
    if set(jd_roles).intersection(set(resume_roles)):
        score += 10
    
    return min(100, score)

def generate_detailed_feedback(ats_score, skill_match, keyword_density, format_score, 
                             experience_relevance, matched_skills, missing_skills, extra_skills):
    """Generate comprehensive feedback with score breakdown"""
    feedback = f"🎯 ATS Score Breakdown:\n\n"
    feedback += f"• Overall ATS Score: {ats_score}%\n"
    feedback += f"• Skills Match: {skill_match}% (40% weight)\n"
    feedback += f"• Keyword Density: {keyword_density}% (25% weight)\n"
    feedback += f"• Format Score: {format_score}% (20% weight)\n"
    feedback += f"• Experience Relevance: {experience_relevance}% (15% weight)\n\n"
    
    feedback += "📊 Detailed Analysis:\n\n"
    
    if ats_score < 50:
        feedback += "❌ Critical Issues: Your resume needs significant improvement to pass ATS screening.\n"
    elif ats_score < 70:
        feedback += "⚠️ Moderate Issues: Your resume has potential but needs optimization.\n"
    else:
        feedback += "✅ Strong Profile: Your resume is well-optimized for ATS systems.\n"
    
    if skill_match < 60:
        feedback += f"\n🔧 Skills Improvement: Only {len(matched_skills)} out of required skills matched.\n"
    
    if missing_skills:
        feedback += f"\n📚 Missing Skills: {', '.join(missing_skills[:5])}{'...' if len(missing_skills) > 5 else ''}\n"
    
    if format_score < 80:
        feedback += f"\n📄 Format Issues: Ensure your resume uses ATS-friendly formatting (score: {format_score}%)\n"
    
    if experience_relevance < 70:
        feedback += f"\n💼 Experience Gap: Consider highlighting more relevant experience (score: {experience_relevance}%)\n"
    
    feedback += f"\n🎯 Recommendations:\n"
    if missing_skills:
        feedback += f"• Add these key skills: {', '.join(missing_skills[:3])}\n"
    feedback += f"• Use more keywords from the job description\n"
    feedback += f"• Ensure clean, simple formatting without tables or graphics\n"
    feedback += f"• Quantify your achievements with numbers and metrics\n"
    
    return feedback
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'pdf'} # Only allow PDF for now

# Create database
with app.app_context():
    db.create_all()
    print("✅ Tables created!")
    print("📂 Database path:", os.path.abspath("database.db"))

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
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

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

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UploadForm()
    if request.method == 'POST':
        resume_file = request.files.get('resume')
        jd_text = form.jd.data
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
            resume_text = extract_text_from_pdf(resume_path)
            if not resume_text:
                flash("Could not extract text from the resume PDF. Please ensure it's a valid PDF.", "danger")
                return redirect(url_for('dashboard'))
            parsed_resume_data = parse_resume(resume_text)
            extracted_skills = extract_skills(parsed_resume_data['raw_text'])
            jd_skills = extract_skills(jd_text)
            comparison_results = compare_skills_and_score(extracted_skills, jd_skills, parsed_resume_data['raw_text'], jd_text)
            return render_template(
                'results.html',
                resume_data=parsed_resume_data,
                extracted_resume_skills=extracted_skills,
                jd_text=jd_text,
                jd_skills=jd_skills,
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)