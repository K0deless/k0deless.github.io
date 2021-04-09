---
layout: default
---

# $ cat about.txt
{:id="about"}

UC3M Cybersecurity students webpage, here you'll find our research posts, papers...

# $ cat team.txt
{:id="team"}

<ul>
{% for member in site.categories.team reversed %}
<li id="{{ member.title }}">{{ member.title }}
<ul>
{% if member.mail %}
<li>{{ member.mail }}</li>
{% endif %}

{% if member.github %}
<li><a href="https://github.com/{{ member.github }}">https://github.com/{{ member.github }}</a></li>
{% endif %}

{% if member.site %}
<li><a href="{{ member.site }}">{{ member.site }}</a></li>
{% endif %}

{% if member.twitter %}
<li><a href="https://twitter.com/{{ member.twitter }}">https://twitter.com/{{ member.twitter }}</a></li>
{% endif %}

</ul>

</li>
{% endfor %}
</ul>

# $ cat projects.txt
{:id="projects"}

<ul>
{% for project in site.categories.projects %}
<li><a href="{{ project.link }}">{{ project.title }}</a> - {{ project.description }} - {{ project.author }}</li>
{% endfor %}
</ul>

# $ cat malware_analysis.txt
{:id="analysis"}

<ul>
{% for project in site.categories.analysis %}
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
{% if site.categories.posts == null %}
No... Not for the moment...
{% endif %}
{% for post in site.categories.posts %}

{% if post. %}
<li>{{ post.title }} :: <a href="{{ post.url | prepend:site.baseurl }}" title="{{ post.description }}">en</a></li>
{% endif %}

{% endfor %}
</ul>

# $ cat articles.txt
{:id="articles"}

<ul>
{% if site.categories.articles == null %}
No... Not yet... Soon =)
{% endif %}
{% for post in site.categories.articles %}

{% if post %}
<li>{{ post.title }} :: <a href="{{ post.link }}" title="{{ post.description }}">en</a></li>
{% endif %}

{% endfor %}
</ul>   

# $ cat publications.txt
{:id="publications"}

<ul>
{% if site.categories.publications == null %}
No... Not yet... Soon =)
{% endif %}
{% for post in site.categories.publications %}

{% if post %}
<ul>
<div>
<h5>
<a href="{{ post.link }}" title="{{ post.title }}">{{ post.title }}</a> :: {{ post.description }}.
</h5>
<h6>
{{post.authors}}.
</h6>
<p>
{{post.conference}}
</p>
</div>
</ul>
{% endif %}

{% endfor %}
</ul>   