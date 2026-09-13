import re
from urllib.parse import urlparse

URGENCY=['urgent','immediately','act now','last chance','expires today','within 24 hours','verify now','account suspended','limited time']
PRIZE=['won','winner','congratulations','lottery','prize','reward','cashback','jackpot','₹','rs.','rupees','crore','lakh']
CREDENTIALS=['password','otp','one time password','pin','cvv','card number','bank details','login','username','aadhaar','pan','personal information']
PAYMENT=['pay','payment','transfer','send money','processing fee','registration fee','deposit','upi','upi id','gift card']
THREAT=['legal action','police','arrest','blocked','suspended','penalty','fine','blacklisted']
SHORTENERS=['bit.ly','tinyurl.com','t.co','goo.gl','is.gd','cutt.ly','rb.gy']

def urls(text): return re.findall(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', text, re.I)
def norm(text): return re.sub(r'\s+',' ',text.lower()).strip()
def hits(text, words): return [x for x in words if x in text]

def url_features(url):
    raw=url.rstrip('.,!?;:)]}')
    p=urlparse(raw if re.match(r'^https?://',raw,re.I) else 'http://'+raw)
    host=p.netloc.lower().split('@')[-1].split(':')[0]; path=(p.path+'?'+p.query).lower(); score=0; reasons=[]
    if host in SHORTENERS: score+=18; reasons.append('URL shortener hides the destination')
    if 'xn--' in host: score+=22; reasons.append('Punycode/IDN domain detected')
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$',host): score+=20; reasons.append('IP address used instead of a domain')
    if len(host)>35: score+=8; reasons.append('Unusually long domain')
    if host.count('.')>=3: score+=7; reasons.append('Many subdomains')
    if host.count('-')>=3: score+=6; reasons.append('Many hyphens in domain')
    if '@' in raw: score+=20; reasons.append('@ symbol can disguise destination')
    if len(raw)>120: score+=6; reasons.append('Unusually long URL')
    sw=[w for w in ['verify','login','secure','account','claim','refund','update','wallet'] if w in path]
    if sw: score+=min(12,len(sw)*4); reasons.append('Sensitive-action words in URL')
    return min(score,60),reasons,host

def analyze_message(text,input_type='auto'):
    t=norm(text); score=8; factors=[]; found=urls(text)
    groups=[('Urgency / pressure language',URGENCY,20),('Prize / unexpected reward claim',PRIZE,22),('Request for credentials or personal information',CREDENTIALS,24),('Payment / money-transfer language',PAYMENT,17),('Threat / account pressure',THREAT,13)]
    results=[]
    for label,words,points in groups:
        h=hits(t,words)
        if h: score+=points; factors.append({'label':label,'detail':', '.join(h[:4])})
    if re.search(r'\b(otp|one[- ]time password)\b',t): score+=12; factors.append({'label':'OTP-related request','detail':'Never share an OTP with an unsolicited sender.'})
    us=0
    for u in found[:5]:
        s,r,h=url_features(u); us+=s
        if r: factors.append({'label':'Suspicious URL indicators','detail':h+': '+'; '.join(r[:3])})
    score+=min(35,us)
    if text.count('!')>=3: score+=5; factors.append({'label':'Excessive punctuation','detail':'Multiple exclamation marks increase pressure/scam likelihood.'})
    letters=sum(c.isalpha() for c in text); caps=sum(c.isupper() for c in text)
    if letters>20 and caps/max(letters,1)>.55: score+=5; factors.append({'label':'Aggressive formatting','detail':'High proportion of uppercase text.'})
    if hits(t,PRIZE) and found: score+=12
    if hits(t,URGENCY) and (hits(t,CREDENTIALS) or hits(t,PAYMENT)): score+=12
    score=max(0,min(99,int(score)))
    level='High' if score>=75 else 'Medium' if score>=45 else 'Low'
    verdict='SCAM RISK' if level=='High' else 'SUSPICIOUS' if level=='Medium' else 'LOW RISK'
    confidence=min(98,max(55,55+abs(score-50)*.8+min(15,len(factors)*2)))
    return {'verdict':verdict,'risk_level':level,'risk_score':score,'confidence':round(confidence,1),'factors':factors,'urls_found':found,'recommendation':'Do not click links, share OTP/passwords, or send money. Verify the sender using an official channel.' if level=='High' else 'Treat this cautiously. Verify the sender, domain, and request independently before taking action.' if level=='Medium' else 'No strong scam signals were detected, but automated analysis cannot guarantee safety.','model':'Explainable hybrid baseline (NLP/rules + URL feature analysis)'}
