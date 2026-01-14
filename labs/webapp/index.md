---
layout: default
title: Web Application Labs
---

# Web Application Labs

{% for page in site.pages %}
{% if page.dir == '/labs/webapp/' and page.name != 'index.md' %}
- [{{ page.title }}]({{ page.url }})
{% endif %}
{% endfor %}
