import os
import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from PIL import Image
from contextlib import contextmanager

# Database configuration
DATABASE_URL = "sqlite:///mydatabase.db"  # SQLite for simplicity
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})  # For SQLite
Session = sessionmaker(bind=engine)

@contextmanager
def get_session():
    """Provide a transactional scope around a series of operations."""
    session = Session()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        st.error(f"Database Error: {e}")
        raise
    finally:
        session.close()

# Define database models
class Patient(Base):
    __tablename__ = 'patients'
    id = Column(Integer, primary_key=True)
    image_path = Column(String, nullable=False)
    complaint = Column(Text, nullable=False)
    diagnosis = Column(String, nullable=True)  # AI/Standard Diagnosis
    code = Column(String, unique=True, nullable=False)

    doctors = relationship("Doctor", back_populates="patient")
    annotations = relationship("Annotation", back_populates="patient")

class Doctor(Base):
    __tablename__ = 'doctors'
    id = Column(Integer, primary_key=True)
    patient_code = Column(String, ForeignKey('patients.code'))
    personal_diagnosis = Column(Text, nullable=True)

    patient = relationship("Patient", back_populates="doctors")

class Annotation(Base):
    __tablename__ = 'annotations'
    id = Column(Integer, primary_key=True)
    patient_code = Column(String, ForeignKey('patients.code'))
    image_description = Column(Text, nullable=False)
    site = Column(String, nullable=False)
    complaints = Column(Text, nullable=False)
    question_relevance = Column(Text, nullable=True)
    additional_questions = Column(Text, nullable=True)

    patient = relationship("Patient", back_populates="annotations")

# Create tables
Base.metadata.create_all(engine)

# Set custom page config
st.set_page_config(
    page_title="Derm Chatbot",
    page_icon="💻",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for UI enhancement
st.markdown("""
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f0f2f6;
        }
        .reportview-container {
            padding: 2rem;
            background: linear-gradient(to bottom right, #ffffff, #e6efff);
        }
        .stButton>button {
            background-color: #4CAF50;
            color: white;
            border-radius: 10px;
            font-size: 16px;
        }
        .stFileUploader>div {
            border-radius: 10px;
            background-color: #f9f9f9;
        }
    </style>
""", unsafe_allow_html=True)

# Utility functions for saving images and generating case codes
def save_image(image) -> str:
    """Saves uploaded image and returns the file path."""
    upload_dir = "uploads"
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, image.name)
    
    # Open and resize the image
    img = Image.open(image)
    img = img.resize((800, 800))  # Resize to a reasonable size
    img.save(file_path)
    
    return file_path

def generate_case_code() -> str:
    """Generates a unique case code."""
    return os.urandom(3).hex().upper()

def fetch_patient_by_code_with_session(session, code: str):
    """
    Fetches patient data by case code within an active session and returns a dictionary.
    """
    patient = session.query(Patient).filter_by(code=code).first()
    if patient:
        # Extract all necessary attributes
        patient_data = {
            'image_path': patient.image_path,
            'complaint': patient.complaint,
            'diagnosis': patient.diagnosis,
            'code': patient.code,
            # Optionally include related data
            'personal_diagnosis': [doctor.personal_diagnosis for doctor in patient.doctors],
            'annotations': [
                {
                    'image_description': annotation.image_description,
                    'site': annotation.site,
                    'complaints': annotation.complaints,
                    'question_relevance': annotation.question_relevance,
                    'additional_questions': annotation.additional_questions
                }
                for annotation in patient.annotations
            ]
        }
        return patient_data
    return None

# Page Functions
def patient_page():
    st.title("🌟 Patient Page")
    st.markdown("""
    ### Instructions:
    1. The agent will ask you around 12 to 15 questions to gather detailed information about your condition. After that, it will generate a case summary. You can ask follow-up questions related to your case and receive tailored responses. While you have the option to generate a summary early by clicking the "Generate Summary" button, it's recommended to answer all the questions first to ensure that no important details are missed. Once all relevant questions have been answered, the agent will automatically generate the summary for you.
    2. Approximate time to complete the questions: 10-15 minutes.
    3. Please upload an image that is in focus and not blurry. It's recommended to take the photo using your device's regular camera app, as the built-in camera window here is smaller and might not produce the best results.
    4. Please enter one complaint at a time.
    5. The data collected may be used for AI research.
    6. This application is an experimental product and not an official medical advice. Please visit your dermatologist for a valid prescription.
    """)
    
    # Collect user inputs
    age = st.text_input("Enter your age")
    sex = st.selectbox("Select your sex", ["Male", "Female", "Other"])
    language = st.selectbox("Select your preferred language: (Only required if you want to talk.)", ["English", "Spanish", "French", "Other"])
    
    agree = st.checkbox("I have read the above instructions and agree to proceed.")

    input_method = st.radio("Select Image Input Method:", ["Upload from Directory", "Use Camera"])

    if input_method == "Upload from Directory":
        uploaded_image = st.file_uploader("Please upload images for analysis", type=["jpg", "png"])
    else:
        uploaded_image = st.camera_input("Please upload images for analysis")

    complaint = st.text_area("Describe Your Complaint:")

    if st.button("Submit Case"):
        if uploaded_image and complaint and agree:
            try:
                image_path = save_image(uploaded_image)
            except Exception as e:
                st.error(f"Image Processing Error: {e}")
                return

            case_code = generate_case_code()

            # Save case to the database
            with get_session() as session:
                new_patient = Patient(
                    image_path=image_path,
                    complaint=complaint,
                    code=case_code
                )
                session.add(new_patient)
            
            st.success(f"🎉 Case Submitted! Your Diagnosis Code: `{case_code}`")
            st.info("Please save this code securely. You will need it to retrieve your case.")
        else:
            st.error("⚠️ Please provide all required information and agree to the instructions.")

def doctor_page():
    st.title("👨‍⚕️ Doctor Page")
    st.markdown("Retrieve patient details using the diagnosis code.")

    case_code = st.text_input("Enter Diagnosis Code:")

    if st.button("Fetch Case"):
        if not case_code.strip():
            st.error("⚠️ Please enter a valid Diagnosis Code.")
            return

        with get_session() as session:
            patient = fetch_patient_by_code_with_session(session, case_code)
        
        if patient:
            # Display patient image
            if os.path.exists(patient['image_path']):
                st.image(patient['image_path'], caption="Patient Image", use_container_width=True)
            else:
                st.warning("⚠️ Image file not found.")

            # Display patient complaint
            st.write(f"**Complaint:** {patient['complaint']}")

            # Display existing diagnoses from doctors, if any
            if patient['personal_diagnosis']:
                st.write("**Doctor's Diagnoses:**")
                for idx, diag in enumerate(patient['personal_diagnosis'], 1):
                    st.write(f"{idx}. {diag}")

            # Input for new diagnosis
            diagnosis = st.text_area("Enter Your Diagnosis:")

            if st.button("Submit Diagnosis"):
                if not diagnosis.strip():
                    st.error("⚠️ Please enter a valid diagnosis.")
                else:
                    with get_session() as session:
                        # Verify patient exists within the new session
                        existing_patient = session.query(Patient).filter_by(code=case_code).first()
                        if existing_patient:
                            new_diagnosis = Doctor(
                                patient_code=case_code,
                                personal_diagnosis=diagnosis
                            )
                            session.add(new_diagnosis)
                            st.success("✅ Diagnosis submitted successfully!")
                        else:
                            st.error("⚠️ No case found for the provided code.")
        else:
            st.error("⚠️ No case found for the provided code.")

def annotator_page():
    st.title("🖌️ Annotator Page")
    st.markdown("Annotate patient data for research purposes.")

    case_code = st.text_input("Enter Diagnosis Code:")

    if st.button("Fetch Case for Annotation"):
        if not case_code.strip():
            st.error("⚠️ Please enter a valid Diagnosis Code.")
            return

        with get_session() as session:
            patient = fetch_patient_by_code_with_session(session, case_code)
        
        if patient:
            # Display patient image
            if os.path.exists(patient['image_path']):
                st.image(patient['image_path'], caption="Patient Image", use_container_width=True)
            else:
                st.warning("⚠️ Image file not found.")

            # Display patient complaint
            st.write(f"**Complaint:** {patient['complaint']}")

            # Annotation Inputs
            description = st.text_area("Image Description:")
            site = st.text_input("Site of Issue:")
            complaints = st.text_area("Additional Complaints:")
            question_relevance = st.text_area("Relevance of Questions:")
            additional_questions = st.text_area("Additional Questions:")

            if st.button("Submit Annotation"):
                if not (description.strip() and site.strip() and complaints.strip()):
                    st.error("⚠️ Please fill in all required annotation fields.")
                else:
                    with get_session() as session:
                        # Verify patient exists within the new session
                        existing_patient = session.query(Patient).filter_by(code=case_code).first()
                        if existing_patient:
                            new_annotation = Annotation(
                                patient_code=case_code,
                                image_description=description,
                                site=site,
                                complaints=complaints,
                                question_relevance=question_relevance,
                                additional_questions=additional_questions
                            )
                            session.add(new_annotation)
                            st.success("✅ Annotation submitted successfully!")
                        else:
                            st.error("⚠️ No case found for the provided code.")
        else:
            st.error("⚠️ No case found for the provided code.")

def data_extraction_page():
    st.title("📊 Data Extraction Page")
    st.markdown("Retrieve and manage patient data for research.")
    
    # Placeholder content
    st.write("To be implemented...")

def dashboard():
    st.title("📈 Dashboard")
    st.markdown("Visualize metrics and experiment results.")
    
    # Placeholder content
    st.write("To be implemented...")

# Navigation
PAGES = {
    "Patient Page": patient_page,
    "Doctor Page": doctor_page,
    "Annotator Page": annotator_page,
    "Data Extraction Page": data_extraction_page,
    "Dashboard": dashboard,
}

st.sidebar.title("Derm Chatbot Navigation")
choice = st.sidebar.radio("Go to:", list(PAGES.keys()))
PAGES[choice]()