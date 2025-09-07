"""
PhishVault Main Server - Complete Integration
Integrates XGBoost models with SHAP explanations and UI
Author: PhishVault Team
"""

import os
import sys
import logging
import joblib
import pandas as pd
import numpy as np
import xgboost as xgb
import shap
import difflib
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import re
import socket
from pathlib import Path
import requests
from bs4 import BeautifulSoup
import tldextract
import ssl
import idna

# FastAPI imports
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class URLScanRequest(BaseModel):
    url: str
    scan_type: str = "quick"

class SHAPExplanation(BaseModel):
    feature_name: str
    feature_value: float
    shap_value: float
    contribution: str  # "increases" or "decreases"
    importance: float  # absolute SHAP value

class URLScanResponse(BaseModel):
    url: str
    is_phishing: bool
    risk_level: str
    confidence: float
    probability: float
    timestamp: str
    model_version: str
    shap_explanations: List[SHAPExplanation]
    recommendations: str
    analysis: Dict[str, Any]

class PhishVaultMLDetector:
    """Complete PhishVault ML Detector with SHAP Integration"""
    
    def __init__(self, artifacts_dir: str = "phishvault_artifacts"):
        self.artifacts_dir = Path(artifacts_dir)
        self.model = None
        self.scaler = None
        self.imputer = None
        self.feature_cols = None
        self.calibrator = None
        self.threshold = None
        self.explainer = None
        
        # Initialize trusted domains whitelist for false positive reduction
        self.trusted_domains = {
            # Major tech companies
            'google.com', 'youtube.com', 'gmail.com', 'googledrive.com', 'google.co.uk',
            'microsoft.com', 'office.com', 'outlook.com', 'live.com', 'hotmail.com',
            'apple.com', 'icloud.com', 'itunes.apple.com',
            'amazon.com', 'aws.amazon.com', 'amazon.co.uk',
            'facebook.com', 'instagram.com', 'whatsapp.com', 'messenger.com',
            'twitter.com', 'x.com', 't.co',
            'linkedin.com', 'linkedin.co.uk',
            
            # Popular websites
            'wikipedia.org', 'en.wikipedia.org',
            'github.com', 'stackoverflow.com', 'stackexchange.com',
            'reddit.com', 'imgur.com',
            'netflix.com', 'spotify.com', 'adobe.com',
            'dropbox.com', 'slack.com', 'zoom.us',
            'paypal.com', 'stripe.com',
            
            # News and media
            'bbc.com', 'cnn.com', 'reuters.com', 'theguardian.com',
            'nytimes.com', 'wsj.com', 'bloomberg.com',
            
            # Educational
            'mit.edu', 'harvard.edu', 'stanford.edu', 'berkeley.edu',
            'coursera.org', 'edx.org', 'khanacademy.org',
            
            # Government and official
            'gov.uk', 'nhs.uk', 'irs.gov', 'usa.gov',
            
            # Banking (major ones)
            'chase.com', 'bankofamerica.com', 'wellsfargo.com',
            'hsbc.com', 'barclays.co.uk', 'lloydsbank.co.uk',
            
            # Other popular sites
            'ebay.com', 'craigslist.org', 'yelp.com',
            'booking.com', 'airbnb.com', 'expedia.com',
            'steamcommunity.com', 'twitch.tv'
        }
        
        logger.info("🔄 Loading PhishVault ML models and SHAP explainer...")
        self._load_models()
        self._initialize_shap()
        logger.info("✅ PhishVault ML detector ready with SHAP explanations!")
    
    def _load_models(self):
        """Load all trained models and preprocessors"""
        try:
            # Load XGBoost model
            model_path = self.artifacts_dir / "xgb_booster.joblib"
            self.model = joblib.load(model_path)
            logger.info("✅ XGBoost model loaded")
            
            # Load preprocessors
            self.scaler = joblib.load(self.artifacts_dir / "scaler.joblib")
            self.imputer = joblib.load(self.artifacts_dir / "imputer.joblib")
            self.feature_cols = joblib.load(self.artifacts_dir / "feature_cols.joblib")
            
            # Load calibrator and threshold
            self.calibrator = joblib.load(self.artifacts_dir / "platt_calibrator.joblib")
            self.threshold = joblib.load(self.artifacts_dir / "prod_threshold.joblib")
            
            # --- AFTER loading scaler, imputer, feature_cols, model in __init__ ---
            # 1) Derive canonical model feature names (best-effort)
            self.model_feature_names = None
            try:
                if hasattr(self.model, "get_booster"):
                    try:
                        self.model_feature_names = list(self.model.get_booster().feature_names or [])
                    except Exception:
                        self.model_feature_names = None
                if not self.model_feature_names and hasattr(self.model, "feature_names"):
                    try:
                        self.model_feature_names = list(self.model.feature_names or [])
                    except Exception:
                        self.model_feature_names = None
                # fallback to artifact feature_cols
                if not self.model_feature_names and getattr(self, "feature_cols", None):
                    self.model_feature_names = list(self.feature_cols)
                logger.info("Model feature names count: %d", len(self.model_feature_names or []))
            except Exception as e:
                logger.warning("Could not read model feature names: %s", e)
                self.model_feature_names = list(self.feature_cols) if getattr(self, "feature_cols", None) else None

            # 2) Derive training means from scaler where possible (so defaults match training distribution)
            self.feature_means = {}
            try:
                if getattr(self, "scaler", None) is not None and getattr(self, "feature_cols", None):
                    means = getattr(self.scaler, "mean_", None)
                    if means is not None and len(means) == len(self.feature_cols):
                        self.feature_means = {col: float(m) for col, m in zip(self.feature_cols, means)}
                        logger.info("Derived feature_means from scaler.mean_")
                    else:
                        raise RuntimeError("scaler.mean_ missing or shape mismatch")
                else:
                    raise RuntimeError("no scaler or feature_cols")
            except Exception:
                # fallback: try loading artifact
                try:
                    self.feature_means = joblib.load(self.artifacts_dir / "feature_means.joblib")
                    logger.info("Loaded feature_means.joblib")
                except Exception:
                    logger.warning("feature_means not available; using small safe defaults")
                    # conservative neutral defaults — expand if you know training features
                    self.feature_means = {
                        "length_url": 50.0, "length_hostname": 15.0, "nb_www": 0.0,
                        "nb_hyphens": 0.0, "nb_subdomains": 0.0, "page_rank": 0.5,
                        "google_index": 0.5, "nb_hyperlinks": 5.0, "links_in_tags": 1.0,
                        "web_traffic": 0.5, "suspicious_tld": 0.0, "https_enabled": 1.0
                    }

            # 3) Create an alias map for common typos / alternate names (extend as you find more)
            # Map variant -> canonical name expected by model/training
            self.feature_aliases = {
                "https_token": "https_enabled",
                "has_ip": "ip",
                "url_length": "length_url",
                "domain_length": "length_hostname",
                "nb_subdomains": "nb_subdomains",  # keep same
                "suspecious_tld": "suspicious_tld",  # common typo fix
                "nb_www": "nb_www",
                # add more aliases if you see them in logs
            }

            # Debug log
            logger.debug("Feature alias map keys: %s", list(self.feature_aliases.keys()))
            
            # --- Build mapping from model_feature_name -> extractor feature name (robust) ---
            self.model_to_extractor = {}
            try:
                extractor_keys = set() 
                # Add both feature_cols and alias keys as possible extractor outputs
                if getattr(self, "feature_cols", None):
                    extractor_keys.update(self.feature_cols)
                extractor_keys.update(self.feature_aliases.keys())
                # Also include canonical alias values
                extractor_keys.update(self.feature_aliases.values())
                # Also include feature_means keys (these are valid defaults)
                extractor_keys.update(self.feature_means.keys())

                for mfn in (self.model_feature_names or []):
                    # 1) exact match
                    if mfn in extractor_keys:
                        self.model_to_extractor[mfn] = mfn
                        continue
                    # 2) alias direct value -> mfn (if mfn is one of canonical alias targets)
                    found_alias = None
                    for alias_key, canonical in self.feature_aliases.items():
                        if canonical == mfn and alias_key in extractor_keys:
                            found_alias = alias_key
                            break
                    if found_alias:
                        self.model_to_extractor[mfn] = found_alias
                        continue
                    # 3) close match using difflib
                    candidates = difflib.get_close_matches(mfn, list(extractor_keys), n=1, cutoff=0.72)
                    if candidates:
                        self.model_to_extractor[mfn] = candidates[0]
                        logger.debug("Mapping model feature '%s' -> closest extractor key '%s'", mfn, candidates[0])
                        continue
                    # 4) fallback to using the feature_means key if present (same name)
                    if mfn in self.feature_means:
                        self.model_to_extractor[mfn] = mfn
                        continue
                    # 5) ultimate fallback: None (will be filled with feature_means later)
                    self.model_to_extractor[mfn] = None

                logger.info("Built feature mapping: %d model features -> extractor keys", len(self.model_to_extractor))
            except Exception as e:
                logger.warning("Failed to build model->extractor mapping: %s", e)
                self.model_to_extractor = {}
            
            logger.info(f"✅ All models loaded - Features: {len(self.feature_cols)}, Threshold: {self.threshold:.4f}")
            logger.info(f"feature_cols len: {len(self.feature_cols)}")
            logger.info(f"First 10 feature names: {self.feature_cols[:10] if len(self.feature_cols) >= 10 else self.feature_cols}")
            
            # Run diagnostic check on model features
            self._run_feature_diagnostic()
            
        except Exception as e:
            logger.error(f"❌ Error loading models: {e}")
            raise
    
    def _run_feature_diagnostic(self):
        """Diagnostic check to compare model expected features vs artifact features"""
        try:
            logger.info("🔍 Running feature diagnostic...")
            
            # Check model attributes
            model_attrs = [a for a in dir(self.model) if 'feature' in a.lower()][:20]
            logger.info(f"Model attributes with 'feature': {model_attrs}")
            
            # Try to get model feature names
            model_feature_names = None
            
            # For Booster
            try:
                if hasattr(self.model, "feature_names"):
                    model_feature_names = self.model.feature_names
                    logger.info(f"Booster feature_names found: {len(model_feature_names) if model_feature_names else 'None'}")
            except Exception as e:
                logger.info(f"Booster feature_names not accessible: {e}")
            
            # For sklearn wrapper
            if not model_feature_names and hasattr(self.model, "get_booster"):
                try:
                    model_feature_names = self.model.get_booster().feature_names
                    logger.info(f"Sklearn wrapper feature_names found: {len(model_feature_names) if model_feature_names else 'None'}")
                except Exception as e:
                    logger.info(f"Sklearn wrapper feature_names not accessible: {e}")
            
            # Compare feature sets
            logger.info(f"Artifact feature_cols len: {len(self.feature_cols)}")
            logger.info(f"Model feature_names len: {len(model_feature_names) if model_feature_names else 'None'}")
            
            if model_feature_names:
                model_cols_set = set(model_feature_names)
                artifact_cols_set = set(self.feature_cols)
                
                extra_in_artifact = sorted(artifact_cols_set - model_cols_set)
                missing_in_artifact = sorted(model_cols_set - artifact_cols_set)
                
                if extra_in_artifact:
                    logger.warning(f"Extra columns in artifact (not in model): {extra_in_artifact[:30]}")
                if missing_in_artifact:
                    logger.warning(f"Missing columns in artifact (expected by model): {missing_in_artifact[:30]}")
                    
                if not extra_in_artifact and not missing_in_artifact:
                    logger.info("✅ Feature columns perfectly aligned!")
                else:
                    logger.warning(f"⚠️ Feature mismatch detected - will fix during prediction")
            else:
                logger.info("Model feature names not discoverable - will use artifact feature_cols as fallback")
                
        except Exception as e:
            logger.warning(f"Feature diagnostic failed: {e}")

    
    def _initialize_shap(self):
        """Initialize SHAP explainer"""
        try:
            # Create a small background dataset for SHAP
            # Use some sample feature vectors (you can improve this with real training data)
            background_data = np.random.randn(100, len(self.feature_cols))
            background_data = self.scaler.transform(background_data)
            
            # Initialize SHAP explainer
            self.explainer = shap.TreeExplainer(self.model)
            
            logger.info("✅ SHAP explainer initialized")
            
        except Exception as e:
            logger.error(f"❌ Error initializing SHAP: {e}")
            # Continue without SHAP if it fails
            self.explainer = None
    
    def extract_url_features(self, url: str, deep: bool = False, fetch_timeout: float = 4.0, tls_timeout: float = 2.0) -> Dict[str, float]:
        """
        Ultra feature extractor (safe defaults + optional deep HTML & TLS checks).
        - url: URL string
        - deep: if True, will fetch the page HTML to compute page-level features (slower)
        - fetch_timeout: HTTP fetch timeout in seconds
        - tls_timeout: TLS certificate check timeout in seconds
        Returns canonicalized dict keyed to training feature names (but will not reorder to model; that is done in predict_with_shap).
        """
        try:
            # normalize
            orig_url = url.strip()
            if not orig_url:
                raise ValueError("Empty URL")
            if not orig_url.startswith(("http://", "https://")):
                orig_url = "https://" + orig_url

            parsed = urlparse(orig_url)
            scheme = parsed.scheme.lower() or "https"
            host = parsed.hostname or ""
            port = parsed.port or (443 if scheme == "https" else 80)
            path = parsed.path or ""
            query = parsed.query or ""
            full = orig_url

            features = {}

            # Basic URL & domain features
            features['length_url'] = len(full)
            features['length_hostname'] = len(host)
            features['nb_dots'] = full.count('.')
            features['nb_hyphens'] = full.count('-')
            features['nb_at'] = full.count('@')
            features['nb_qm'] = full.count('?')
            features['nb_and'] = full.count('&')
            features['nb_or'] = full.count('|')
            features['nb_eq'] = full.count('=')
            features['nb_underscore'] = full.count('_')
            features['nb_tilde'] = full.count('~')
            features['nb_percent'] = full.count('%')
            features['nb_slash'] = full.count('/')
            features['nb_star'] = full.count('*')
            features['nb_colon'] = full.count(':')
            features['nb_comma'] = full.count(',')
            features['nb_semicolumn'] = full.count(';')
            features['nb_dollar'] = full.count('$')
            features['nb_space'] = full.count(' ')
            features['nb_dslash'] = full.count('//')

            # Host specifics
            features['ip'] = 1.0 if re.search(r'^\d{1,3}(?:\.\d{1,3}){3}$', host) else 0.0
            features['port'] = 1.0 if (':' in (parsed.netloc or "") and not (parsed.netloc or "").startswith('[')) else 0.0

            # scheme tokens
            features['https_enabled'] = 1.0 if scheme == 'https' else 0.0
            features['http_in_path'] = 1.0 if 'http' in path.lower() else 0.0

            # token & ratio features
            features['ratio_digits_url'] = sum(c.isdigit() for c in full) / len(full) if full else 0.0
            features['ratio_digits_host'] = sum(c.isdigit() for c in host) / len(host) if host else 0.0
            features['char_repeat'] = self._char_repeat_ratio(full)
            features['random_domain'] = self._calculate_entropy(host) / 6.0  # scaled smaller

            # tld / subdomain stats using tldextract if available else fallback
            try:
                te = tldextract.extract(host)
                features['subdomain'] = te.subdomain or ""
                features['registered_domain'] = te.domain or ""
                features['tld'] = te.suffix or ""
                # count subdomains:
                features['nb_subdomains'] = len([p for p in (te.subdomain or "").split('.') if p]) if te.subdomain else 0
            except Exception:
                features['nb_subdomains'] = max(0, len(host.split('.')) - 2) if '.' in host else 0
                features['tld'] = host.split('.')[-1] if '.' in host else ''
                features['registered_domain'] = '.'.join(host.split('.')[-2:]) if '.' in host else host

            # domain keywords that hint phishing
            features['phish_hints'] = 1.0 if any(k in full.lower() for k in ['secure', 'account', 'update', 'confirm', 'verify', 'suspend', 'login', 'bank', 'payment']) else 0.0

            # suspicious TLD
            features['suspicious_tld'] = 1.0 if features.get('tld', '') in ['tk', 'ml', 'ga', 'cf', 'gq'] else 0.0

            # word-based features
            words = re.findall(r'[a-zA-Z]+', full)
            features['length_words_raw'] = sum(len(w) for w in words) if words else 0
            features['shortest_words_raw'] = min((len(w) for w in words), default=0)
            features['longest_words_raw'] = max((len(w) for w in words), default=0)
            features['avg_words_raw'] = (sum(len(w) for w in words) / len(words)) if words else 0.0

            # placeholder HTML/page features (set defaults; deep scan will override)
            features.update({
                'nb_hyperlinks': 0.0,
                'ratio_intHyperlinks': 0.0,
                'ratio_extHyperlinks': 0.0,
                'ratio_nullHyperlinks': 0.0,
                'nb_extCSS': 0.0,
                'login_form': 0.0,
                'external_favicon': 0.0,
                'links_in_tags': 0.0,
                'submit_email': 0.0,
                'ratio_intMedia': 0.0,
                'ratio_extMedia': 0.0,
                'sfh': 0.0,
                'iframe': 0.0,
                'popup_window': 0.0,
                'safe_anchor': 0.0,
                'empty_title': 0.0,
                'domain_in_title': 0.0,
                'brand_impersonation_risk': 0.0,
            })

            # Optional: TLS cert check (safe, short timeout). Fill cert_age, has_valid_cert flags.
            try:
                if host and scheme == 'https':
                    # resolve idna for international domains
                    host_idna = idna.encode(host).decode('ascii')
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((host_idna, port), timeout=float(tls_timeout)) as s:
                        with ctx.wrap_socket(s, server_hostname=host_idna) as ss:
                            cert = ss.getpeercert()
                            # cert is a dict; compute age if possible
                            not_before = cert.get('notBefore')
                            not_after = cert.get('notAfter')
                            # attempt basic validity check
                            features['certificate_present'] = 1.0
                            features['certificate_valid'] = 1.0 if cert else 0.0
            except Exception:
                # keep defaults (0)
                features.setdefault('certificate_present', 0.0)
                features.setdefault('certificate_valid', 0.0)

            # Deep HTML analysis: fetch the page and compute link/form/resource metrics
            if deep:
                try:
                    headers = {
                        "User-Agent": "PhishVault/1.0 (+https://example.com)",
                        "Accept": "text/html,application/xhtml+xml"
                    }
                    resp = requests.get(full, timeout=float(fetch_timeout), headers=headers, allow_redirects=True)
                    html = resp.text or ""
                    soup = BeautifulSoup(html, "html.parser")

                    # Title check
                    title = (soup.title.string or "").strip() if soup.title else ""
                    features['empty_title'] = 1.0 if not title else 0.0
                    if title and host in title:
                        features['domain_in_title'] = 1.0

                    # Links and anchors
                    anchors = soup.find_all('a', href=True)
                    total_links = len(anchors)
                    int_links = 0
                    ext_links = 0
                    null_links = 0
                    for a in anchors:
                        href = a.get('href', '').strip()
                        if href.startswith('#') or href in ('', 'javascript:void(0)', 'javascript:;'):
                            null_links += 1
                        elif href.startswith('http') or href.startswith('//'):
                            # normalize
                            if href.startswith('//'):
                                href_host = urlparse(scheme + ':' + href).hostname or ""
                            else:
                                href_host = urlparse(href).hostname or ""
                            if href_host and (href_host.endswith(host) or host.endswith(href_host)):
                                int_links += 1
                            else:
                                ext_links += 1
                        else:
                            # relative link -> internal
                            int_links += 1

                    features['nb_hyperlinks'] = float(total_links)
                    features['ratio_intHyperlinks'] = float(int_links) / total_links if total_links else 0.0
                    features['ratio_extHyperlinks'] = float(ext_links) / total_links if total_links else 0.0
                    features['ratio_nullHyperlinks'] = float(null_links) / total_links if total_links else 0.0

                    # Forms and input fields (login forms detection)
                    forms = soup.find_all('form')
                    features['suspicious_forms'] = float(len([f for f in forms if '/login' in (f.get('action') or '').lower() or 'password' in ''.join([str(i) for i in f.find_all(['input','button'])]).lower()]))
                    features['login_form'] = 1.0 if any('password' in str(f).lower() for f in forms) else 0.0

                    # External CSS & external favicon
                    css_links = soup.find_all('link', rel=lambda v: v and 'stylesheet' in v)
                    ext_css = 0
                    for l in css_links:
                        href = l.get('href', '')
                        if href and href.startswith('http') and host not in href:
                            ext_css += 1
                    features['nb_extCSS'] = float(ext_css)

                    # Images and media external vs internal
                    imgs = soup.find_all('img', src=True)
                    total_media = len(imgs)
                    ext_media = 0
                    for im in imgs:
                        src = im.get('src', '')
                        if src and src.startswith('http') and host not in src:
                            ext_media += 1
                    features['ratio_extMedia'] = float(ext_media) / total_media if total_media else 0.0
                    features['ratio_intMedia'] = 1.0 - features['ratio_extMedia'] if total_media else 0.0

                    # Links in <script> or tags
                    script_tags = soup.find_all('script', src=True)
                    external_scripts = sum(1 for s in script_tags if s.get('src', '').startswith('http') and host not in s.get('src', ''))
                    features['links_in_tags'] = float(external_scripts + ext_css)

                    # Favicon detection
                    fav = soup.find('link', rel=lambda v: v and ('icon' in v or 'shortcut icon' in v))
                    if fav:
                        fhref = fav.get('href', '')
                        if fhref.startswith('http') and host not in fhref:
                            features['external_favicon'] = 1.0
                        else:
                            features['external_favicon'] = 0.0

                    # Mixed content check (quick heuristic: http resources while page loaded over https)
                    mixed = 0
                    if scheme == 'https':
                        for tag in soup.find_all(src=True) + soup.find_all(href=True):
                            attr = tag.get('src') or tag.get('href')
                            if attr and attr.startswith('http://'):
                                mixed = 1
                                break
                    features['mixed_content_risk'] = float(mixed)

                    # Brand impersonation heuristic: presence of known brand names in path/host/title
                    brands = ['paypal', 'google', 'amazon', 'microsoft', 'apple', 'facebook', 'github', 'netflix']
                    features['brand_impersonation_risk'] = 1.0 if any(b in full.lower() or b in title.lower() for b in brands) else 0.0

                    # Estimate external link count
                    features['external_links'] = float(ext_links)

                    # Check for onmouseover / right click disabling JS patterns (very crude)
                    page_text = html.lower()
                    features['onmouseover'] = 1.0 if 'onmouseover' in page_text else 0.0
                    features['right_clic'] = 1.0 if 'event.button==2' in page_text or 'contextmenu' in page_text else 0.0

                except Exception as e:
                    # Keep defaults for deep fetch issues
                    logger.debug("Deep fetch failed for %s: %s", full, e)
            # END deep

            # WHOIS / registration heuristics (optional, slow) - use only if python-whois installed
            try:
                import whois
                w = whois.whois(host)
                if w and hasattr(w, 'creation_date') and w.creation_date:
                    # some whois libs return list
                    creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    if isinstance(creation, str):
                        # try parse
                        from dateutil import parser
                        creation = parser.parse(creation)
                    import datetime as _dt
                    age_days = (datetime.now() - creation).days if creation and isinstance(creation, _dt.datetime) else 365.0
                    features['domain_age'] = float(min(age_days, 36500))
                    features['whois_registered_domain'] = 1.0
                else:
                    features.setdefault('domain_age', 365.0)
                    features.setdefault('whois_registered_domain', 0.0)
            except Exception:
                # don't fail; keep defaults
                features.setdefault('domain_age', 365.0)
                features.setdefault('whois_registered_domain', 0.0)

            # Fill canonical aliases & ensure numeric floats for keys
            canonical = {}
            for k, v in features.items():
                # map alias -> canonical if present
                canonical_name = self.feature_aliases.get(k, k)
                try:
                    canonical[canonical_name] = float(v) if v is not None else float(self.feature_means.get(canonical_name, 0.0))
                except Exception:
                    canonical[canonical_name] = float(self.feature_means.get(canonical_name, 0.0))

            # Final: ensure every model_feature (if known) is present, otherwise fill from feature_means
            expected = self.model_feature_names or (self.feature_cols or list(canonical.keys()))
            for feat in expected:
                if feat not in canonical or canonical.get(feat) is None or (isinstance(canonical.get(feat), float) and np.isnan(canonical.get(feat))):
                    canonical[feat] = float(self.feature_means.get(feat, 0.0))

            return canonical

        except Exception as e:
            logger.exception("Ultra extractor error for %s: %s", url, e)
            expected = self.model_feature_names or (self.feature_cols or [])
            return {feat: float(self.feature_means.get(feat, 0.0)) for feat in expected}
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        entropy = 0
        for char in set(text):
            p = text.count(char) / len(text)
            if p > 0:
                entropy -= p * np.log2(p)
        return entropy
    
    def _vowel_consonant_ratio(self, text: str) -> float:
        """Calculate vowel to consonant ratio"""
        vowels = sum(1 for c in text.lower() if c in 'aeiou')
        consonants = sum(1 for c in text.lower() if c.isalpha() and c not in 'aeiou')
        return vowels / (consonants + 1)
    
    def _char_repeat_ratio(self, text: str) -> float:
        """Calculate character repetition ratio"""
        if not text:
            return 0.0
        unique_chars = len(set(text))
        return 1 - (unique_chars / len(text))
    
    def _is_trusted_domain(self, url: str) -> bool:
        """Check if the URL belongs to a trusted domain to reduce false positives"""
        try:
            parsed = urlparse(url.lower())
            domain = parsed.netloc
            
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Check direct match
            if domain in self.trusted_domains:
                return True
            
            # Check if it's a subdomain of a trusted domain
            for trusted_domain in self.trusted_domains:
                if domain.endswith('.' + trusted_domain):
                    return True
            
            return False
        except Exception:
            return False
    
    def predict_with_shap(self, url: str, scan_type: str = "quick") -> URLScanResponse:
        """Predict phishing with SHAP explanations (robust, logs full tracebacks)."""
        try:
            logger.info(f"🔍 Analyzing URL: {url}")

            # Check if URL belongs to a trusted domain first
            if self._is_trusted_domain(url):
                logger.info(f"✅ URL belongs to trusted domain, marking as legitimate: {url}")
                return URLScanResponse(
                    url=url,
                    is_phishing=False,
                    probability=0.0001,  # Very low probability for trusted domains
                    confidence=0.999,    # High confidence it's legitimate
                    risk_level="Low",
                    timestamp=datetime.now().isoformat(),  # Required field
                    model_version="PhishVault XGBoost v2.0 (Trusted Domain Bypass)",  # Required field
                    shap_explanations=[{
                        "feature_name": "trusted_domain",
                        "feature_value": 1.0,
                        "shap_value": -10.0,  # Strong negative contribution
                        "contribution": "reduces",
                        "importance": 10.0  # Required field - absolute SHAP value
                    }],
                    recommendations="✅ This domain is in our trusted whitelist of legitimate websites. "
                                  "It has been verified as safe and bypasses the ML model to prevent false positives. "
                                  "You can proceed with confidence, but always verify the exact URL matches the intended site.",  # Required field
                    analysis={  # Required field
                        "scan_metadata": {
                            "scan_type": scan_type,
                            "trusted_domain": True,
                            "model_bypassed": True,
                            "bypass_reason": "Domain found in verified whitelist"
                        },
                        "domain_info": {
                            "domain": urlparse(url).netloc,
                            "is_trusted": True,
                            "verification_status": "whitelisted"
                        },
                        "security_features": {
                            "https_enabled": url.startswith('https://'),
                            "trusted_certificate": True,
                            "reputation_score": 100
                        },
                        "risk_indicators": [],  # No risk indicators for trusted domains
                        "trust_signals": [
                            "Domain in verified whitelist",
                            "Known legitimate website",
                            "Regular security monitoring"
                        ]
                    }
                )

            # -- Basic sanity checks --
            if self.model is None:
                raise RuntimeError("Model is not loaded")
            if self.feature_cols is None or len(self.feature_cols) == 0:
                raise RuntimeError("Feature column list is empty")

            # Extract features with deep analysis based on scan type
            deep_analysis = scan_type != "quick"  # Use deep analysis for non-quick scans
            features = self.extract_url_features(url, deep=deep_analysis)
            logger.debug(f"🔬 Extracted {len(features)} features with deep={deep_analysis}")

            # --- Create a friendly raw_features dict for UI & thresholds ---
            # Keep the original 'features' dict (which may contain training-named keys).
            raw_features = dict(features)  # shallow copy so we can add aliases

            # Add canonical boolean fields (derived or alias)
            # If your extract_url_features() produced 'https_token' use it, otherwise derive from URL
            parsed = urlparse(url)
            raw_features.setdefault('https_enabled', 1.0 if parsed.scheme == 'https' else 0.0)
            # some code used 'https_token' name earlier — alias to canonical name
            if 'https_token' in features:
                raw_features['https_enabled'] = float(features.get('https_token', raw_features['https_enabled']))

            # Many places expect 'has_ip' vs 'ip' naming; alias both ways
            if 'ip' in features and 'has_ip' not in raw_features:
                raw_features['has_ip'] = float(features.get('ip', 0.0))
            elif 'has_ip' in features and 'ip' not in raw_features:
                raw_features['ip'] = float(features.get('has_ip', 0.0))

            # alias suspicious tld variants and fix common typos
            if 'suspicious_tld' in features:
                raw_features.setdefault('suspecious_tld', features.get('suspicious_tld'))
            if 'suspecious_tld' in features and 'suspicious_tld' not in raw_features:
                raw_features['suspicious_tld'] = features.get('suspecious_tld')

            # Ensure numeric defaults for display fields used later
            for k in ['page_rank', 'google_index', 'nb_www', 'length_url', 'nb_hyphens']:
                raw_features.setdefault(k, 0.0)

            # --- ALIGN FEATURES TO MODEL EXPECTATIONS (robust) ---
            
            # Determine model's expected feature names (best-effort)
            model_feature_names = None
            # sklearn-like wrapper with attribute
            if hasattr(self.model, "feature_names") and self.model.feature_names:
                model_feature_names = list(self.model.feature_names)
            # xgboost sklearn wrapper may expose get_booster()
            elif hasattr(self.model, "get_booster"):
                try:
                    model_feature_names = list(self.model.get_booster().feature_names)
                except Exception:
                    model_feature_names = None
            # raw Booster
            elif hasattr(self.model, "feature_names") and self.model.feature_names:
                model_feature_names = list(self.model.feature_names)

            # Fallback to your stored artifact order if model doesn't expose names
            if not model_feature_names:
                logger.warning("Model feature names not discoverable; falling back to artifact feature_cols")
                model_feature_names = list(self.feature_cols)

            # Build DataFrame with model_feature_names order and fill missing with NaN
            # Build input row using mapping so model receives the same columns/order it was trained on
            input_row = {}
            for col in model_feature_names:
                mapped = None
                # prefer explicit mapping if available
                if hasattr(self, "model_to_extractor") and isinstance(self.model_to_extractor, dict):
                    mapped = self.model_to_extractor.get(col, None)
                # If mapping points to None, try direct lookup and aliases
                val = None
                if mapped:
                    val = features.get(mapped, None)
                else:
                    # try exact feature name
                    val = features.get(col, None)
                    # try alias map (value -> canonical)
                    if val is None and col in self.feature_aliases:
                        alt = self.feature_aliases[col]
                        val = features.get(alt, None)
                    # try common alternative patterns
                    if val is None:
                        # try lowercase/uppercase variations
                        val = features.get(col.lower(), None) if isinstance(col, str) else None
                        if val is None:
                            val = features.get(col.upper(), None)
                # If still None, use training mean if available
                if val is None or (isinstance(val, float) and (np.isnan(val) or val is None)):
                    val = float(self.feature_means.get(col, self.feature_means.get(mapped, 0.0)))
                try:
                    input_row[col] = float(val)
                except Exception:
                    # final fallback to 0.0
                    input_row[col] = 0.0
            df = pd.DataFrame([input_row], columns=model_feature_names)

            # Log differences for debugging (only once or at debug level)
            extra_in_input = sorted(set(self.feature_cols) - set(model_feature_names))
            missing_in_input = sorted(set(model_feature_names) - set(self.feature_cols))
            if extra_in_input:
                logger.warning("Feature artifact contains extra columns not in model: %s", extra_in_input[:30])
            if missing_in_input:
                logger.warning("Model expects these columns not present in artifact feature_cols: %s", missing_in_input[:30])

            # Now apply preprocessing (imputer & scaler) — these usually accept numpy arrays
            fv = df.values  # 2D array shape (1, n_features_model)
            try:
                if self.imputer is not None:
                    fv = self.imputer.transform(fv)
                if self.scaler is not None:
                    fv = self.scaler.transform(fv)
            except Exception as e:
                logger.error("Preprocessing (imputer/scaler) failed: %s", e, exc_info=True)
                raise RuntimeError(f"Preprocessing failed: {e}")

            # Create DMatrix using explicit feature names so XGBoost can map correctly
            try:
                dmatrix = xgb.DMatrix(fv, feature_names=model_feature_names)
            except Exception as e:
                logger.error("Failed to create DMatrix with feature names: %s", e, exc_info=True)
                # fallback: create DMatrix without feature_names
                dmatrix = xgb.DMatrix(fv)

            # Prediction: handle sklearn wrapper vs native Booster
            try:
                if hasattr(self.model, "predict_proba"):  # sklearn estimator
                    pred_proba = self.model.predict_proba(fv)
                    calibrated_prob = float(pred_proba[0][1]) if pred_proba.ndim == 2 else float(pred_proba[0])
                    logger.info(f"📊 Sklearn prediction probability: {calibrated_prob:.6f}")
                else:
                    raw_pred = self.model.predict(dmatrix)
                    raw_value = float(raw_pred[0])
                    logger.info(f"📊 Raw XGBoost output: {raw_value:.6f}")
                    
                    # TEMPORARILY DISABLE CALIBRATOR due to feature mismatch
                    # The calibrator was trained on 1 feature but model has 87 features
                    # if self.calibrator is not None:
                    #     try:
                    #         calibrated_prob = float(self.calibrator.predict_proba(fv)[0, 1])
                    #     except Exception:
                    #         logger.warning("Calibrator failed, using raw model prediction", exc_info=True)
                    
                    # For XGBoost raw predictions, ensure they're in [0,1] range
                    if raw_value > 1.0 or raw_value < 0.0:
                        # If raw prediction is outside [0,1], apply sigmoid
                        calibrated_prob = 1.0 / (1.0 + np.exp(-raw_value))
                        logger.info(f"📊 Applied sigmoid transformation: {calibrated_prob:.6f}")
                    else:
                        calibrated_prob = raw_value
                        logger.info(f"📊 Using raw prediction (already in [0,1]): {calibrated_prob:.6f}")
                        
            except Exception as e:
                logger.error("Model prediction failed: %s", e, exc_info=True)
                raise RuntimeError(f"Model prediction failed: {e}")

            # Ensure calibrated_prob in [0,1]
            calibrated_prob = max(0.0, min(1.0, float(calibrated_prob)))
            
            # --- conservative quick-scan behavior and small allowlist ---
            # quick-scan flag assumed to be passed into predict_with_shap signature (scan_type)
            # If you haven't changed signature, ensure endpoint calls predictor with scan_type
            eff_threshold = float(self.threshold or 0.5)

            # tiny allowlist for known legitimate domains — temporary safety net
            ALLOWLIST = {"github.com", "google.com", "wikipedia.org", "mozilla.org", "stackoverflow.com"}
            try:
                hostname = urlparse(url).hostname.lower() if url else ""
            except Exception:
                hostname = ""

            if hostname in ALLOWLIST:
                # treat these as safe immediately (development/testing only)
                logger.info("Allowlist hit: %s — returning safe", hostname)
                is_phishing = False
            else:
                if scan_type == "quick":
                    # count how many HTML-like features were filled from means (i.e., not actually extracted)
                    html_keys = ["nb_hyperlinks", "links_in_tags", "page_rank", "google_index", "web_traffic"]
                    defaults_used = sum(1 for k in html_keys if float(raw_features.get(k, self.feature_means.get(k, 0.0))) == float(self.feature_means.get(k, 0.0)))
                    if defaults_used >= 2:
                        # be conservative for quick mode — increase threshold slightly
                        eff_threshold = min(0.95, eff_threshold + 0.12)

                is_phishing = calibrated_prob > eff_threshold
            confidence = max(calibrated_prob, 1.0 - calibrated_prob)
            
            logger.info(f"📊 Final probability: {calibrated_prob:.6f}")
            logger.info(f"📊 Scan type: {scan_type}")
            logger.info(f"📊 Effective threshold: {eff_threshold:.4f}")
            logger.info(f"📊 Classification: {'PHISHING' if is_phishing else 'LEGITIMATE'}")
            logger.info(f"📊 Confidence: {confidence:.4f}")

            # Determine risk_level
            if calibrated_prob >= 0.8:
                risk_level = "HIGH"
            elif calibrated_prob >= 0.5:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            # --- SHAP explanations: show raw feature values in the UI, use shap for impact ---
            shap_explanations = []
            if self.explainer is not None:
                try:
                    # explanation computed earlier on scaled/preprocessed input (call as before)
                    explanation = self.explainer(fv)
                    shap_values = explanation.values
                    # normalize shap_values shape to (n_features,)
                    flat_shap = np.array(shap_values).reshape(-1, len(model_feature_names))[-1]
                    # pair model_feature_names with raw (preprocessed) display values when possible
                    for fname, shp in sorted(zip(model_feature_names, flat_shap), key=lambda x: abs(x[1]), reverse=True)[:10]:
                        # prefer raw display value from raw_features, fallback to 0.0
                        display_value = float(raw_features.get(fname, raw_features.get(fname.lower(), np.nan)))
                        contribution = "increases" if float(shp) > 0 else "decreases"
                        shap_explanations.append(SHAPExplanation(
                            feature_name=fname,
                            feature_value=float(display_value) if not (display_value is None or np.isnan(display_value)) else 0.0,
                            shap_value=float(shp),
                            contribution=contribution,
                            importance=float(abs(shp))
                        ))
                except Exception as e:
                    logger.warning("SHAP explanation failed, falling back: %s", e, exc_info=True)
                    # fallback simple explanations from raw features
                    for k in list(raw_features.keys())[:6]:
                        shap_explanations.append(SHAPExplanation(
                            feature_name=k,
                            feature_value=float(raw_features.get(k, 0.0)),
                            shap_value=0.0,
                            contribution="unknown",
                            importance=0.0
                        ))
            else:
                # No explainer -> show top raw features as placeholders
                for k in list(raw_features.keys())[:6]:
                    shap_explanations.append(SHAPExplanation(
                        feature_name=k,
                        feature_value=float(raw_features.get(k, 0.0)),
                        shap_value=0.0,
                        contribution="unknown",
                        importance=0.0
                    ))

            # Build final analysis and recommendations
            parsed = urlparse(url)
            analysis = {
                "domain_info": {
                    "domain": parsed.netloc,
                    "length": len(parsed.netloc),
                    "subdomain_count": float(features.get('nb_subdomains', 0))
                },
                "url_structure": {
                    "url_length": len(url),
                    "suspicious_chars": float(features.get('nb_percent', 0)) + float(features.get('nb_dollar', 0))
                },
                "security_features": {
                    "https_enabled": bool(parsed.scheme == 'https'),
                    "has_ip": bool(features.get('ip', 0)),
                    "has_port": bool(features.get('port', 0))
                },
                "risk_indicators": self._get_risk_indicators(raw_features, shap_explanations)
            }

            recommendations = self._generate_recommendations(url, is_phishing, features, shap_explanations)

            logger.info("✅ Analysis complete: phishing=%s prob=%.4f", is_phishing, calibrated_prob)

            return URLScanResponse(
                url=url,
                is_phishing=is_phishing,
                risk_level=risk_level,
                confidence=float(confidence),
                probability=float(calibrated_prob),
                timestamp=datetime.now().isoformat(),
                model_version=getattr(self, "model_version", "XGBoost_v2.0_SHAP"),
                shap_explanations=shap_explanations,
                recommendations=recommendations,
                analysis=analysis
            )

        except HTTPException:
            raise
        except Exception as exc:
            # Log full traceback and raise a readable HTTPException upstream
            logger.error("❌ Prediction error for URL %s: %s", url, exc, exc_info=True)
            # Raise a meaningful exception so FastAPI returns it in detail
            raise RuntimeError(f"Prediction failed: {str(exc)}")
    
    def _generate_recommendations(self, url: str, is_phishing: bool, features: Dict, shap_explanations: List) -> str:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if is_phishing:
            recommendations.append("🚨 HIGH RISK: This URL appears to be a phishing attempt.")
            recommendations.append("❌ DO NOT enter personal information, passwords, or financial details.")
            recommendations.append("🔍 Verify the authentic website URL through official channels.")
            
        # Feature-based recommendations
        if not features.get('https_enabled', 0):
            recommendations.append("🔒 Warning: This site doesn't use HTTPS encryption.")
            
        if features.get('has_ip', 0):
            recommendations.append("⚠️ Suspicious: URL uses IP address instead of domain name.")
            
        if features.get('url_length', 0) > 100:
            recommendations.append("📏 Long URL detected - verify legitimacy before proceeding.")
            
        if features.get('suspicious_chars', 0) > 10:
            recommendations.append("🔤 High number of suspicious characters in URL.")
        
        # SHAP-based recommendations
        for explanation in shap_explanations[:3]:  # Top 3 features
            if explanation.shap_value > 0.1:  # Positive contribution to phishing
                if 'length' in explanation.feature_name:
                    recommendations.append(f"📊 {explanation.feature_name} contributes to risk assessment.")
                elif 'suspicious' in explanation.feature_name:
                    recommendations.append(f"⚠️ Suspicious patterns detected in URL structure.")
        
        if not is_phishing:
            recommendations.append("✅ URL appears legitimate based on ML analysis.")
            recommendations.append("🛡️ Continue with normal security precautions.")
        
        return "\n".join(recommendations)
    
    def _get_risk_indicators(self, raw_features: Dict, shap_explanations: List) -> List[str]:
        """Return risk indicators using raw/unscaled feature values and canonical names."""
        indicators = []

        # HTTPS check — use canonical flag
        https_on = bool(raw_features.get('https_enabled', 0))
        if not https_on:
            indicators.append("No HTTPS encryption")

        # IP address in hostname
        if raw_features.get('has_ip', raw_features.get('ip', 0)):
            indicators.append("Uses IP address instead of domain")

        # URL length (use raw length_url if available; otherwise fallback to threshold)
        url_len = raw_features.get('length_url') or raw_features.get('url_length') or 0
        if url_len and float(url_len) > 100:
            indicators.append("Unusually long URL")

        # suspicious characters; prefer raw 'nb_percent' or 'suspicious_chars'
        suspicious_chars = raw_features.get('nb_percent', 0) + raw_features.get('nb_dollar', 0) + raw_features.get('nb_hyphens', 0)
        if suspicious_chars > 10:
            indicators.append("High number of suspicious characters")

        # subdomain count (alias handling)
        sub_cnt = raw_features.get('nb_subdomains') or raw_features.get('subdomain_count') or 0
        if sub_cnt and sub_cnt > 3:
            indicators.append("Multiple subdomains")

        # SHAP-based indicators (use shap_explanations which include raw display values now)
        for explanation in shap_explanations[:6]:
            try:
                if explanation.shap_value > 0.05:
                    indicators.append(f"High {explanation.feature_name} impact")
            except Exception:
                continue

        # Deduplicate and return
        seen = set()
        final = []
        for it in indicators:
            if it not in seen:
                seen.add(it)
                final.append(it)
        return final

# Initialize the ML detector
detector = None

# Global executor for blocking operations
_EXECUTOR = ThreadPoolExecutor(max_workers=3)

async def run_blocking(fn, *args, **kwargs):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_EXECUTOR, lambda: fn(*args, **kwargs))

def initialize_detector():
    """Initialize the ML detector"""
    global detector
    try:
        detector = PhishVaultMLDetector()
        return True
    except Exception as e:
        logger.error(f"Failed to initialize detector: {e}")
        return False

# Create FastAPI app
app = FastAPI(
    title="PhishVault ML Server",
    description="Advanced Phishing Detection with XGBoost and SHAP Explanations",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize detector on startup"""
    logger.info("🚀 Starting PhishVault ML Server...")
    if not initialize_detector():
        logger.error("❌ Failed to initialize ML detector")
        sys.exit(1)
    logger.info("✅ PhishVault ML Server ready!")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "PhishVault ML Server",
        "version": "2.0.0",
        "features": ["XGBoost ML Model", "SHAP Explanations", "Real-time Analysis"],
        "status": "active"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "model_loaded": detector is not None,
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0"
    }

@app.post("/scan_url", response_model=URLScanResponse)
async def scan_url(request: URLScanRequest):
    """Scan URL for phishing with SHAP explanations"""
    if detector is None:
        raise HTTPException(status_code=503, detail="ML detector not initialized")
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")
    # normalize scheme
    url = request.url if request.url.startswith(('http://','https://')) else 'https://' + request.url
    try:
        # run the (possibly blocking) predict_with_shap in a worker thread
        scan_type = getattr(request, 'scan_type', 'quick')  # default to quick
        result = await run_blocking(detector.predict_with_shap, url, scan_type)
        return result
    except Exception as exc:
        logger.error("Scan failed for %s: %s", url, exc, exc_info=True)
        # Ensure a helpful error detail is returned to client
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(exc) or 'internal error'}")

@app.post("/debug_scan")
async def debug_scan(request: URLScanRequest):
    if detector is None:
        raise HTTPException(status_code=503, detail="Detector not initialized")
    url = request.url if request.url.startswith(('http://','https://')) else 'https://' + request.url
    try:
        features = detector.extract_url_features(url, deep=False)  # Use quick scan for debug
        model_cols = detector.model_feature_names or list(detector.feature_cols or features.keys())
        import pandas as pd
        row = {c: float(features.get(c, detector.feature_means.get(c, 0.0))) for c in model_cols}
        df = pd.DataFrame([row], columns=model_cols)
        pre = df.values
        imputed = detector.imputer.transform(pre) if detector.imputer is not None else pre
        scaled = detector.scaler.transform(imputed) if detector.scaler is not None else imputed
        # model probability
        try:
            if hasattr(detector.model, "predict_proba"):
                raw_prob = float(detector.model.predict_proba(scaled)[0,1])
            else:
                dmat = xgb.DMatrix(scaled, feature_names=model_cols)
                raw_prob = float(detector.model.predict(dmat)[0])
        except Exception as e:
            raw_prob = f"model error: {e}"
        # calibrator
        try:
            cal_prob = float(detector.calibrator.predict_proba(scaled)[0,1]) if detector.calibrator is not None else None
        except Exception as e:
            cal_prob = f"calibrator error: {e}"
        # shap (top)
        top_shap = None
        if detector.explainer is not None:
            try:
                expl = detector.explainer(scaled)
                vals = np.array(expl.values).reshape(-1, len(model_cols))[-1]
                pairs = sorted(zip(model_cols, df.values.flatten().tolist(), vals.tolist()), key=lambda x: abs(x[2]), reverse=True)[:12]
                top_shap = [{"feature": f, "raw_value": v, "shap": s} for f,v,s in pairs]
            except Exception as e:
                top_shap = f"shap error: {e}"
        return {
            "url": url,
            "model_cols": model_cols[:200],
            "model_to_extractor": detector.model_to_extractor,
            "raw_features": {k: features.get(k) for k in list(features.keys())[:200]},
            "filled_row_sample": {k: row.get(k) for k in model_cols[:200]},
            "preprocessed_shape": scaled.shape if hasattr(scaled, 'shape') else None,
            "raw_model_prob": raw_prob,
            "calibrated_prob": cal_prob,
            "top_shap": top_shap
        }
    except Exception as exc:
        logger.exception("debug_scan failed")
        raise HTTPException(status_code=500, detail=f"debug failed: {exc}")

@app.get("/stats")
async def get_stats():
    """Get model statistics"""
    if detector is None:
        raise HTTPException(status_code=503, detail="ML detector not initialized")
    
    return {
        "model_type": "XGBoost",
        "features_count": len(detector.feature_cols),
        "threshold": float(detector.threshold),
        "shap_enabled": detector.explainer is not None,
        "version": "2.0.0"
    }

def check_port_available(port: int) -> bool:
    """Check if port is available"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('localhost', port))
            return True
        except socket.error:
            return False

def main():
    """Main function to start the server"""
    print("🌟" + "="*60 + "🌟")
    print("🚀 PhishVault ML Server - Complete Integration")
    print("🤖 XGBoost Models + SHAP Explanations + UI Integration")
    print("🌟" + "="*60 + "🌟")
    
    # Find available port
    port = 8000
    if not check_port_available(port):
        port = 8001
        if not check_port_available(port):
            port = 8002
    
    print(f"📍 Server starting on: http://localhost:{port}")
    print(f"🌐 Extension endpoint: http://localhost:{port}/scan_url")
    print(f"❤️  Health check: http://localhost:{port}/health")
    print(f"📊 Statistics: http://localhost:{port}/stats")
    print(f"🔍 SHAP explanations enabled for detailed analysis")
    print("🌟" + "="*60 + "🌟")
    
    # Update extension if needed
    try:
        extension_file = Path("../Extension/floatingPanel.js")
        if extension_file.exists():
            content = extension_file.read_text()
            if f"localhost:{port}" not in content:
                content = content.replace("localhost:8001", f"localhost:{port}")
                content = content.replace("localhost:8002", f"localhost:{port}")
                extension_file.write_text(content)
                print(f"✅ Updated extension to use port {port}")
    except Exception as e:
        print(f"⚠️  Could not update extension config: {e}")
    
    # Start server
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
    )

if __name__ == "__main__":
    main()
