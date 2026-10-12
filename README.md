# Customer Retention and Analytics System

An interactive, data-driven application that analyses customer purchasing behaviour, performs Recency–Frequency–Monetary (RFM) segmentation, and delivers decision-focused retention insights. Built with Python, Pandas, Streamlit, and Power BI.

---

## Project Overview

Customer retention is critical for sustainable business growth. This project processes raw transactional data to identify high-value customers, highlight retention risks, and provide actionable recommendations for retention strategies.

The application cleans raw datasets, computes RFM scores, classifies customer segments, predicts retention risk, and provides an interactive visual dashboard for decision-makers. A separate technical workspace enforces role-based access, audit logging, and dataset versioning.

---

## Key Features

- **Data Ingestion and Validation:** Automated schema checks, country label standardisation, and duplicate detection before cleaning.
- **Data Cleaning:** Handles missing values, standardises data types, preserves cancellations for audit, and produces an analysis-ready dataset.
- **RFM Feature Engineering:** Calculates Recency, Frequency, and Monetary scores per customer and classifies them into segments (Champions, Loyal Customers, Potential Loyalists, At Risk, Lost / Low Value).
- **Retention Risk Classification:** Applies a 60-day inactivity rule grounded in the dataset's 75th percentile inter-purchase interval, with a separate HighValue indicator for priority targeting.
- **Predictive Modelling:** Compares Logistic Regression and Random Forest on a temporal test set using cross-validated ROC-AUC, Precision, Recall, and F1-score.
- **Interactive Streamlit Dashboard:** Real-time filtering, segment exploration, product and market-basket analysis, geography, and a scenario simulator.
- **Power BI Integration:** Executive reporting layer built from the approved published outputs.
- **Role-Based Access Control:** Separate technical and business workspaces with audit logging, dataset versioning, and a governed publish step.

---

## Tech Stack

| Layer | Tools |
|-------|-------|
| Core language | Python 3.10+ |
| Data processing | Pandas, NumPy |
| Machine learning | scikit-learn (Logistic Regression, Random Forest) |
| Interactive web UI | Streamlit |
| Authentication | streamlit-authenticator, bcrypt |
| Visualisation | Plotly |
| Market basket analysis | mlxtend (optional) |
| Configuration | PyYAML |
| Persistent user store | SQLite (Python standard library) |
| Business reporting | Power BI Desktop |
| Version control | Git, GitHub |

---

## Data Source

The application is designed for the **UCI Online Retail II** dataset (1,067,371 transaction records, December 2009 – December 2011).

The dataset is available from the UCI Machine Learning Repository:
<https://archive.ics.uci.edu/dataset/502/online+retail+ii>

---

## Repository Structure

```
customer-retention-system/
├── data/                          # Raw and processed datasets
│   ├── raw/
│   └── processed/
├── notebooks/                     # Exploratory and modelling notebooks
├── powerbi/                       # Power BI reporting assets
├── streamlit_app/                 # Streamlit application package
│   ├── app.py                     # Main application entry point
│   ├── config.yaml                # Non-sensitive application configuration
│   ├── requirements.txt           # Python dependencies
│   ├── .gitignore
│   ├── data/
│   │   └── users.db               # Persistent RBAC user store (created on first run)
│   ├── model_artifacts/
│   │   ├── model_cv_results.csv
│   │   ├── temporal_test_predictions.csv
│   │   ├── model_confusion_matrix.csv   (optional)
│   │   ├── model_derived_metrics.csv    (optional)
│   │   └── model_selection_summary.csv  (optional)
│   └── outputs/
│       ├── audit/
│       │   └── audit_trail.csv
│       └── published/
│           ├── archive/           # Timestamped publication snapshots
│           ├── power_bi/          # Approved Power BI hand-off datasets
│           └── team_outputs/      # Seven governed team CSV outputs
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.10 or later
- Power BI Desktop (Windows only — optional, for the reporting layer)

Confirm Python is installed:

```bash
python --version
```

### 1. Clone the repository

```bash
git clone https://github.com/Colucci-HACKERY/RNI-Customer-Retention-System.git
cd RNI-Customer-Retention-System/streamlit_app
```

### 2. Create and activate a virtual environment

**macOS / Linux:**

```bash
python -m venv venv
source venv/bin/activate
```

**Windows (PowerShell):**

```powershell
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure authentication and secrets

The application requires two configuration files before it can run:

**`config.yaml`** (non-sensitive):

```yaml
roles:
  technical: technical
  business: business

cookie:
  name: rni_retention_app
  key: change_this_in_production
  expiry_days: 30
```

**`.streamlit/secrets.toml`** (sensitive — do not commit):

```toml
[cookie]
name = "rni_retention_app"
key = "your_secret_key_here"
expiry_days = 30

[power_bi]
dashboard_url = "https://app.powerbi.com/view?r=..."

[bootstrap_users.technical_admin]
email = "admin@example.com"
name = "Technical Admin"
password = "replace_with_bcrypt_hash"
role = "technical"

[bootstrap_users.business_user]
email = "business@example.com"
name = "Business User"
password = "replace_with_bcrypt_hash"
role = "business"
```

Bootstrap users are inserted into the SQLite user store on first launch only. After that, all user management happens through the in-app User Management page.

### 5. Run the application

```bash
streamlit run app.py
```

The app will open at <http://localhost:8501>.

### 6. Log in

Use one of the bootstrap accounts you defined in `secrets.toml`.

---

## Application Workflow

The system enforces a governed, role-separated pipeline:

**Technical workspace (data preparation):**

1. Upload the retail transaction dataset (CSV or Excel)
2. Run data validation and review the quality score
3. Run data cleaning — cancellations are preserved and flagged, not discarded
4. Generate RFM features and customer segments
5. Review the model evaluation page (required before publishing)
6. Publish approved outputs to the governed hand-off directories

**Business workspace (reporting consumption):**

1. View pipeline status and the current approved publication
2. Explore Quick Analytics — customer value, products, geography, market basket
3. Open the Power BI dashboard for the full executive view

---

## Power BI Reporting Layer

The Power BI dashboard connects to the approved datasets in `outputs/published/power_bi/`. It provides three reporting pages:

- **Executive Overview** — total, active, and at-risk customer counts, RFM segment distribution, retention exposure, priority tiers
- **Priority Customers** — high-value at-risk list, recency vs frequency scatter, segment priority composition
- **Retention Impact Simulator** — scenario slider, projected reactivation, protected customer value

The Power BI file itself is stored in the `powerbi/` directory of this repository.

---

## Known Limitations

- The dataset is historical (2009–2011) and reflects a single UK-based online retailer.
- Churn is operational (60-day inactivity), not contractual, because the dataset contains no verified defection event.
- Records without a usable Customer ID are excluded from customer-level RFM analysis.
- The pipeline uses a file-based hand-off between Streamlit and Power BI rather than a live database connection.
- Some published CSV files are excluded from the repository due to size limits. They are regenerated automatically when the pipeline is run and published.

---

## Team and Acknowledgements

This project was developed as a group effort by a team of student analysts at the Botswana School of Business Science:

| Team Member | Contribution |
|-------------|--------------|
| Abale Moatshe | Data cleaning, RFM engineering, model evaluation |
| Elias Pako J. Mothibapula | Repository architecture, Streamlit application development, RFM algorithm implementation |
| Jasmin Clotyda G. Khamfore | Project documentation, literature review, report writing |
| Laone Sydney Akanyang | Data preparation, Power BI dashboard development, project documentation |

Supervisor: **Kagiso Motshidisi**

---

## License

This project is open-source and available under the MIT License.
