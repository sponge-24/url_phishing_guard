import requests
from urllib.parse import urlparse
import tldextract
from bs4 import BeautifulSoup
import re

def get_legitimate_probability(domain, api_key):

    BASE_URL = 'https://www.virustotal.com/api/v3/domains/'

    url = f"{BASE_URL}{domain}/votes"
    headers = {'x-apikey': api_key}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:

        data = response.json().get('data', [])


        harmless_count = sum(1 for vote in data if vote['attributes']['verdict'] == 'harmless')
        total_votes = len(data)

        legitimacy_prob = harmless_count / total_votes if total_votes > 0 else 0

        return legitimacy_prob
    else:
        return float(0)

def extract_url_features(url,api_key):
    key = api_key
    features = {}

    features["URLLength"] = len(url)
    parsed_url = urlparse(url)
    extracted = tldextract.extract(url)

    features["DomainLength"] = len(parsed_url.netloc)
    features["TLD"] = extracted.suffix
    features["CharContinuationRate"] = sum(1 for i in range(len(url)-1) if url[i].isalpha() == url[i+1].isalpha()) / len(url)
    features["TLDLegitimateProb"] = get_legitimate_probability(parsed_url.netloc,api_key = key)
    features["TLDLength"] = len(extracted.suffix)
    features["NoOfSubDomain"] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0

    features["LetterRatioInURL"] = sum(c.isalpha() for c in url) / len(url)
    features["NoOfDegitsInURL"] = sum(c.isdigit() for c in url)
    features["DegitRatioInURL"] = features["NoOfDegitsInURL"] / len(url)


    features["NoOfOtherSpecialCharsInURL"] = len(re.findall(r'[=?@#^&*<>~]', url))
    features["SpacialCharRatioInURL"] = features["NoOfOtherSpecialCharsInURL"] / len(url)
    features["IsHTTPS"] = 1 if parsed_url.scheme == "https" else 0

    try:
        response = requests.get(url, timeout=5)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')

        features["LineOfCode"] = html.count('\n')
        features["LargestLineLength"] = max(len(line) for line in html.split('\n'))
        features["HasTitle"] = 1 if soup.title else 0

        if soup.title:
            title_text = soup.title.text.lower()
            domain_name = extracted.domain.lower()
            domain_len = len(domain_name)
            
            
            def longest_common_substring(s1, s2):
                m = [[0] * (1 + len(s2)) for _ in range(1 + len(s1))]
                longest = 0
                for x in range(1, 1 + len(s1)):
                    for y in range(1, 1 + len(s2)):
                        if s1[x-1] == s2[y-1]:
                            m[x][y] = m[x-1][y-1] + 1
                            longest = max(longest, m[x][y])
                return longest
            
            lcs_length = longest_common_substring(domain_name, title_text)
            
            substring_ratio = (lcs_length / domain_len)*100 if domain_len > 0 else 0
            exact_match = 100.0 if domain_name in title_text else 0

            features["DomainTitleMatchScore"] = substring_ratio
        else:
            features["DomainTitleMatchScore"] = 0

        features["HasFavicon"] = 1 if soup.find("link", rel="icon") else 0

        try:
            robots_response = requests.get(parsed_url.scheme + "://" + parsed_url.netloc + "/robots.txt", timeout=5)
            features["Robots"] = 1 if robots_response.status_code == 200 else 0
        except:
            features["Robots"] = 0

        features["IsResponsive"] = 1 if soup.find("meta", attrs={"name": "viewport"}) else 0
        features["HasDescription"] = 1 if soup.find("meta", attrs={"name": "description"}) else 0


        features["NoOfPopup"] = html.lower().count("window.open")
        features["NoOfiFrame"] = len(soup.find_all("iframe"))
        features["HasExternalFormSubmit"] = 1 if any(form.get("action") and extracted.domain not in form.get("action", "") for form in soup.find_all("form")) else 0

        social_patterns = {

            'links': [
                r'(?:www\.)?(?:facebook|fb)\.com',
                r'(?:www\.)?twitter\.com',
                r'(?:www\.)?linkedin\.com',
                r'(?:www\.)?instagram\.com',
                r'(?:www\.)?tiktok\.com',
                r'(?:www\.)?pinterest\.com',
                r'(?:www\.)?reddit\.com',
                r'(?:www\.)?youtube\.com',
                r't\.me',
                r'(?:www\.)?weibo\.com',
                r'(?:www\.)?vk\.com',
            ],
            

            'buttons': [
                'share-button',
                'social-share',
                'share-icon',
                'follow-button',
                'social-icon',
                'social-media',
            ],
            
            'elements': [
                'social',
                'share',
                'follow',
                'network',
                'connect',
            ],
            
            'meta': [
                'og:social',
                'twitter:card',
                'fb:app_id',
                'instagram:',
            ],
            
            'text': [
                'follow us',
                'share this',
                'connect with us',
                'find us on',
                'join us on',
            ]
        }

        has_social = False

        for pattern in social_patterns['links']:
            if re.search(pattern, html.lower()):
                has_social = True
                break
                
        if not has_social:
  
            for button in social_patterns['buttons']:
                if soup.find(attrs={'class': re.compile(button, re.I)}) or \
                   soup.find(attrs={'id': re.compile(button, re.I)}):
                    has_social = True
                    break
                    
        if not has_social:
    
            for element in social_patterns['elements']:
                if soup.find(attrs={'class': re.compile(f'.*{element}.*', re.I)}) or \
                   soup.find(attrs={'id': re.compile(f'.*{element}.*', re.I)}):
                    has_social = True
                    break
                    
        if not has_social:

            for meta in social_patterns['meta']:
                if soup.find('meta', attrs={'property': re.compile(meta, re.I)}) or \
                   soup.find('meta', attrs={'name': re.compile(meta, re.I)}):
                    has_social = True
                    break
                    
        if not has_social:

            for text in social_patterns['text']:
                if re.search(text, html.lower()):
                    has_social = True
                    break

        features["HasSocialNet"] = 1 if has_social else 0
        features["HasSubmitButton"] = 1 if soup.find("input", {"type": "submit"}) else 0
        features["HasHiddenFields"] = 1 if soup.find("input", {"type": "hidden"}) else 0

        features["Bank"] = 1 if any(keyword in html.lower() for keyword in ["bank", "secure", "login"]) else 0
        features["Pay"] = 1 if any(keyword in html.lower() for keyword in ["pay", "payment", "checkout"]) else 0

        features["HasCopyrightInfo"] = 1 if "©" in html or "copyright" in html.lower() else 0

        features["NoOfImage"] = len(soup.find_all("img"))
        features["NoOfCSS"] = len(soup.find_all("link", rel="stylesheet"))
        features["NoOfJS"] = len(soup.find_all("script"))


        all_links = [a.get("href") for a in soup.find_all("a") if a.get("href")]
        features["NoOfSelfRef"] = sum(1 for link in all_links if extracted.domain in link)
        features["NoOfEmptyRef"] = sum(1 for link in all_links if link in ["", "#"])
        features["NoOfExternalRef"] = sum(1 for link in all_links if extracted.domain not in link and link.startswith("http"))



    except requests.RequestException:
        for key in ["LineOfCode", "LargestLineLength", "HasTitle", "DomainTitleMatchScore", "HasFavicon","Robots", "IsResponsive", "HasDescription", "NoOfPopup", "NoOfiFrame", "HasExternalFormSubmit", "HasSocialNet", "HasSubmitButton", "HasHiddenFields", "Bank", "Pay", "HasCopyrightInfo", "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef"]:
            features[key] = 0

    return features