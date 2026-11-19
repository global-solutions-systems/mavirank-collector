"""Bot detection by user agent.

Ordered rules, first match wins (specific tokens before generic ones). Names use only
``[A-Za-z0-9 ._()/-]`` and are at most 60 characters, as the query API expects.
All Googlebot crawlers (including Image, Video, News) are reported as ``Googlebot``
with a ``bot_variant``; other Google crawlers keep their own name.
"""
from __future__ import annotations

import re
from typing import List, NamedTuple, Optional, Pattern, Tuple

KINDS = ("search", "ai", "seo", "social", "shopping", "monitor", "script", "other")
VARIANTS = ("Smartphone", "Desktop", "Image", "Video", "News")

# (regex, name, kind, google_family)
_RULES: List[Tuple[str, str, str, bool]] = [
    # Google: exact crawler tokens first
    (r"Googlebot-Image", "Googlebot", "search", True),
    (r"Googlebot-Video", "Googlebot", "search", True),
    (r"Googlebot-News", "Googlebot", "search", True),
    (r"Google-InspectionTool", "Google-InspectionTool", "search", True),
    (r"Storebot-Google", "Storebot-Google", "shopping", True),
    (r"AdsBot-Google", "AdsBot-Google", "search", True),
    (r"Mediapartners-Google", "Google AdSense", "search", True),
    (r"Googlebot", "Googlebot", "search", True),
    (r"GoogleOther", "GoogleOther", "ai", True),
    (r"Google-CloudVertexBot", "Google-CloudVertexBot", "ai", True),
    (r"FeedFetcher-Google", "Google FeedFetcher", "other", True),
    (r"Google-Site-Verification", "Google Site Verification", "other", True),
    (r"Google-Read-Aloud", "Google Read Aloud", "other", True),
    # other search engines
    (r"bingbot|BingPreview|msnbot|adidxbot", "Bingbot", "search", False),
    (r"Applebot", "Applebot", "search", False),
    (r"YandexBot|YandexImages|YandexMobileBot|YandexRenderResourcesBot", "YandexBot", "search", False),
    (r"DuckDuckBot|DuckAssistBot", "DuckDuckBot", "search", False),
    (r"Baiduspider", "Baiduspider", "search", False),
    (r"PetalBot", "PetalBot", "search", False),
    (r"SeznamBot", "SeznamBot", "search", False),
    (r"Qwantbot|Qwantify", "Qwantbot", "search", False),
    (r"Sogou", "Sogou", "search", False),
    (r"Yeti/|NaverBot", "Naver", "search", False),
    (r"MojeekBot", "MojeekBot", "search", False),
    (r"Amzn-SearchBot", "Amazon Search", "search", False),
    # AI crawlers and agents
    (r"GPTBot", "GPTBot", "ai", False),
    (r"ChatGPT-User", "ChatGPT-User", "ai", False),
    (r"OAI-SearchBot", "OAI-SearchBot", "ai", False),
    (r"ClaudeBot|Claude-User|Claude-SearchBot|Claude-Web|anthropic-ai", "ClaudeBot", "ai", False),
    (r"PerplexityBot|Perplexity-User", "PerplexityBot", "ai", False),
    (r"CCBot", "CCBot", "ai", False),
    (r"Bytespider", "Bytespider", "ai", False),
    (r"Amazonbot", "Amazonbot", "ai", False),
    (r"meta-externalagent|meta-externalfetcher|FacebookBot", "Meta AI", "ai", False),
    (r"cohere-ai|cohere-training-data-crawler", "Cohere", "ai", False),
    (r"MistralAI-User", "MistralAI", "ai", False),
    (r"Diffbot", "Diffbot", "ai", False),
    (r"YouBot", "YouBot", "ai", False),
    (r"ExaBot|ExaSearchBot", "Exa", "ai", False),
    (r"ElevenlabsCrawler|ElevenLabs", "ElevenLabs", "ai", False),
    (r"AI2Bot", "AI2Bot", "ai", False),
    (r"Timpibot", "Timpibot", "ai", False),
    # SEO tools
    (r"AhrefsBot|AhrefsSiteAudit", "AhrefsBot", "seo", False),
    (r"SemrushBot|SiteAuditBot|SplitSignalBot", "SemrushBot", "seo", False),
    (r"MJ12bot", "MJ12bot", "seo", False),
    (r"DotBot", "DotBot", "seo", False),
    (r"rogerbot", "rogerbot", "seo", False),
    (r"SISTRIX", "SISTRIX", "seo", False),
    (r"Screaming Frog", "Screaming Frog", "seo", False),
    (r"DataForSeoBot", "DataForSeoBot", "seo", False),
    (r"BLEXBot", "BLEXBot", "seo", False),
    (r"SEOkicks", "SEOkicks", "seo", False),
    (r"serpstatbot", "serpstatbot", "seo", False),
    (r"Barkrowler", "Barkrowler", "seo", False),
    (r"Seekport", "Seekport", "seo", False),
    (r"SERankingBacklinksBot|SE Ranking", "SE Ranking", "seo", False),
    (r"mavirank-bot", "mavirank", "seo", False),
    # social previews
    (r"facebookexternalhit|facebookcatalog", "Facebook", "social", False),
    (r"Twitterbot", "Twitterbot", "social", False),
    (r"LinkedInBot", "LinkedInBot", "social", False),
    (r"Pinterestbot|Pinterest/", "Pinterest", "social", False),
    (r"Slackbot", "Slackbot", "social", False),
    (r"WhatsApp", "WhatsApp", "social", False),
    (r"TelegramBot", "TelegramBot", "social", False),
    (r"Discordbot", "Discordbot", "social", False),
    (r"redditbot", "redditbot", "social", False),
    (r"Mastodon/", "Mastodon", "social", False),
    # shopping
    (r"AmazonProductDiscovery|AmazonProductBot", "Amazon Product Discovery", "shopping", False),
    (r"idealo", "idealo", "shopping", False),
    (r"Geedo", "Geedo", "shopping", False),
    (r"PriceRunner", "PriceRunner", "shopping", False),
    # monitoring and performance
    (r"UptimeRobot", "UptimeRobot", "monitor", False),
    (r"Pingdom", "Pingdom", "monitor", False),
    (r"StatusCake", "StatusCake", "monitor", False),
    (r"Site24x7", "Site24x7", "monitor", False),
    (r"Better Uptime|BetterStack", "Better Stack", "monitor", False),
    (r"Chrome-Lighthouse|Google Page Speed|PageSpeed", "Lighthouse", "monitor", False),
    (r"GTmetrix", "GTmetrix", "monitor", False),
    (r"Checkly", "Checkly", "monitor", False),
    # scripts and libraries
    (r"^curl/", "curl", "script", False),
    (r"^Wget/", "Wget", "script", False),
    (r"python-requests|python-urllib|Python-urllib|aiohttp|python-httpx|Scrapy", "Python", "script", False),
    (r"Go-http-client", "Go", "script", False),
    (r"^Java/|okhttp|Apache-HttpClient", "Java", "script", False),
    (r"node-fetch|axios/|undici", "Node.js", "script", False),
    (r"libwww-perl", "Perl", "script", False),
    (r"GuzzleHttp|^PHP/", "PHP", "script", False),
    (r"HeadlessChrome|PhantomJS", "Headless browser", "script", False),
    (r"zgrab|masscan|Nmap|Nuclei|sqlmap|Nikto", "Scanner", "script", False),
    # catch-all
    (r"(?i)bot\b|bot/|crawler|spider|crawl|slurp|scraper|fetcher", "Other bots", "other", False),
]


class Rule(NamedTuple):
    regex: Pattern[str]
    name: str
    kind: str
    google: bool


RULES = [Rule(re.compile(p), name, kind, google) for p, name, kind, google in _RULES]


class BotMatch(NamedTuple):
    name: str
    kind: str
    variant: Optional[str]
    google: bool  # member of the Google crawler family (verifiable against Google's IP lists)


def googlebot_variant(user_agent: str) -> str:
    if "Googlebot-Image" in user_agent:
        return "Image"
    if "Googlebot-Video" in user_agent:
        return "Video"
    if "Googlebot-News" in user_agent:
        return "News"
    if "Mobile" in user_agent or "Android" in user_agent:
        return "Smartphone"
    return "Desktop"


def classify(user_agent: str) -> Optional[BotMatch]:
    if not user_agent or user_agent == "-":
        return None
    for rule in RULES:
        if rule.regex.search(user_agent):
            variant = googlebot_variant(user_agent) if rule.name == "Googlebot" else None
            return BotMatch(rule.name, rule.kind, variant, rule.google)
    return None
