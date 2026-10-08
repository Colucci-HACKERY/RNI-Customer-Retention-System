Customer Retention and Analytics System
An interactive, data-driven application designed to analyze customer behavior, perform Recency-Frequency-Monetary (RFM) segmentation, and deliver decision-focused insights to improve customer retention. Built using Python, Pandas, Streamlit, and Power BI.

**Project Overview**
Customer retention is critical for sustainable business growth. This project processes raw transactional data to identify high-value customers, highlight churn risks, and provide actionable recommendations for retention strategies.
The application cleans raw datasets, computes RFM scores, classifies customer segments, and provides an interactive visual dashboard for decision-makers.
Key Features
Data Cleaning and Preprocessing: Handles missing values, standardizes data types, and prepares raw transactional datasets for analysis.
RFM Segmentation: Calculates Recency, Frequency, and Monetary scores to categorize customers into meaningful segments (such as Champions, At-Risk, Loyal Customers, or Lost).
Interactive Dashboard: Built with Streamlit to enable real-time filtering, segment exploration, and visual analytics.
Power BI Integration: Executive summary visuals and structured data models for corporate reporting.
Tech Stack and Tools
Core Language: Python
Data Processing and Analytics: Pandas, NumPy
Interactive Web UI: Streamlit
Data Visualization: Plotly, Power BI
Version Control: Git and GitHub

Team and Acknowledgments
This project was developed as a group effort by a team of student analysts:
**Elias Pako Mothibapula** – Contributor / Data analyst 
Contributed to repository architecture, core Python logic, RFM algorithm implementation, Streamlit UI integration, and team code coordination.
**Laone Akanyang** – Contributor / Data Analyst
Contributed to data cleaning, dataset preparation, statistical calculations, powerBI dashboard and team code coordination

some csv files could not be uploaded because of their size
Getting Started
Prerequisites
Ensure you have Python installed on your system:
python --version
Installation
Clone the repository:
git clone https://github.com/EliasMothibapula/customer-retention-system.git
cd customer-retention-system
Create and activate a virtual environment (optional but recommended):
python -m venv venv
source venv/bin/activate

Install required dependencies:
pip install -r requirements.txt

Run the Streamlit application:
streamlit run app.py

License
This project is open-source and available under the MIT License.
