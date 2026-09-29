"""
Dataset management for ML Model Service
Provides:
- Initial curated dataset D (Phishing / Spam vs Legitimate / Ham)
- Dynamic augmentation with newly collected user feedback D'
"""
from typing import List, Dict, Any, Tuple


INITIAL_DATASET: List[Dict[str, Any]] = [
    # Phishing / Spam samples (1)
    {"text": "URGENT: Your account has been suspended! Click here to verify your credentials immediately.", "label": 1},
    {"text": "Congratulations! You have won $1,000,000 in the international lottery. Send your bank details now.", "label": 1},
    {"text": "Security Alert: Unauthorized login attempt detected from Russia. Reset your password at http://bit.ly/fake-auth", "label": 1},
    {"text": "Your parcel delivery failed due to unpaid tax. Update delivery address and pay $2 fee here immediately.", "label": 1},
    {"text": "Payroll update: Action required to receive your end of month bonus. Open the attachment immediately.", "label": 1},
    {"text": "Claim your free Bitcoin gift voucher now! Limited spots available for the next 10 minutes.", "label": 1},
    {"text": "Dear customer, your PayPal account is restricted. Re-authenticate your debit card to restore access.", "label": 1},
    {"text": "Dear colleague, please review the attached invoice #88921.exe and process payment today.", "label": 1},
    {"text": "Final warning: Your cloud storage is 99% full. Click here to upgrade before your files are deleted permanently.", "label": 1},
    {"text": "Exclusive loan offer: Instant approval up to $50,000 with 0% interest for 12 months. Apply now!", "label": 1},

    # Legitimate / Ham samples (0)
    {"text": "Hi Team, please find attached the meeting minutes and action items from yesterday's sync.", "label": 0},
    {"text": "Can we schedule a quick call tomorrow at 2 PM to review the project roadmap and milestones?", "label": 0},
    {"text": "The seminar on Modern Cryptography and PQC will be held in Lecture Hall 3 this Wednesday at 4 PM.", "label": 0},
    {"text": "Thank you for submitting your research paper. The peer review feedback has been shared on the portal.", "label": 0},
    {"text": "Please remember to submit your timesheet before Friday evening to avoid payroll delays.", "label": 0},
    {"text": "Here is the updated git repository link for our group project on secure model serving.", "label": 0},
    {"text": "The library will remain open until midnight during the mid-semester examination week.", "label": 0},
    {"text": "Hi Dr. Sardar, could you please clarify the parameters used for the lattice-based KEM in assignment 1?", "label": 0},
    {"text": "Don't forget to push your code commits to the main branch before the pull request review.", "label": 0},
    {"text": "Let me know if you would like to grab lunch together after the machine learning tutorial session.", "label": 0},
]


class Dataset:
    """Manages base dataset D and feedback dataset D'."""

    def __init__(self, samples: List[Dict[str, Any]] = None):
        self._samples = list(samples) if samples else list(INITIAL_DATASET)

    def add_feedback(self, text: str, label: int) -> None:
        self._samples.append({"text": text, "label": label})

    def get_data(self) -> Tuple[List[str], List[int]]:
        texts = [s["text"] for s in self._samples]
        labels = [s["label"] for s in self._samples]
        return texts, labels

    def __len__(self) -> int:
        return len(self._samples)


def get_initial_dataset() -> Dataset:
    return Dataset(INITIAL_DATASET)
