---
layout: default
---

# $ cat about.txt
{:id="about"}

Reverse Engineer, Malware Analyst and sometimes low level programmer (C, C++, ASM, Python)...

On this webpage I will upload some of my analysis, research papers or I will reference my tools.

I hope you like it.

# $ cat team.txt
{:id="team"}

<ul>
{% for member in site.categories.team reversed %}
<li id="{{ member.title }}">{{ member.title }}
<ul>
<li>{{ member.mail }}</li>
<li><a href="https://github.com/{{ member.github }}">https://github.com/{{ member.github }}</a></li>
<li><a href="{{ member.site }}">{{ member.site }}</a></li>
</ul>
</li>
{% endfor %}
</ul>

# $ cat projects.txt
{:id="projects"}

<ul>
{% for project in site.categories.projects %}
<li><a href="{{ project.link }}">{{ project.title }}</a> - {{ project.description }}</li>
{% endfor %}
</ul>

# $ cat tools.txt
{:id="tools"}

<ul>
{% for tool in site.categories.tools %}
<li><a href="{{ tool.link }}">{{ tool.title }}</a> - {{ tool.description }}</li>
{% endfor %}
</ul>

# $ cat talks.txt
{:id="talks"}

<ul>
{% for talk in site.categories.talks %}
<li><a href="{{ talk.link }}" title="{{ talk.description }}">{{ talk.title }}</a> at {{ talk.where }}</li>
{% endfor %}
</ul>

# $ cat posts.txt
{:id="posts"}

<ul>
{{ site.categories.posts }}
{% for post in site.categories.posts %}

{% if post. %}
<li>{{ post.title }} :: <a href="{{ post.url }}" title="{{ post.description }}">en</a> :: <a href="{{ post.pt }}" title="{{ post.description_pt }}">pt_br</a></li>

{% endfor %}
</ul>

# $ cat articles.txt
{:id="articles"}

<ul>

{% for post in site.categories.articles %}

{% if post %}
<li>{{ post.title }} :: <a href="{{ post.url }}" title="{{ post.description }}">en</a> :: <a href="{{ post.pt }}" title="{{ post.description_pt }}">pt_br</a></li>

{% endfor %}
</ul>
