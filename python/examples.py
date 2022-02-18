#!/usr/bin/env python

from py4j.java_gateway import JavaGateway
gateway = JavaGateway()

# callbacks
callbacks = gateway.entry_point

# helpers
helpers = callbacks.getHelpers()

# sitemap
sm = callbacks.getSiteMap('h')

# out of scope host names
set([a.getHost() for a in sm if not callbacks.isInScope(a.getUrl())])

# in scope items
ssm = [a for a in sm if callbacks.isInScope(a.getUrl())]

# get headers
def get_headers(request):
    head = request.split(b'\r\n\r\n')[0].decode('utf8')
    return [(a.split(':', 1)[0].rstrip(), a.split(':', 1)[1].rstrip().lstrip())  for a in head.split('\r\n') if ':' in a]


# in scope site map items
ssm = [a for a in sm if callbacks.isInScope(a.getUrl())]

# get user agents for in scope hosts
set([b[1] for a in ssm for b in get_headers(a.getRequest()) if b[0].lower() == 'user-agent'])


# get user agents used per host in scope
host_user_agents = { a: [] for a in set([a.getHost() for a in ssm])}
for entry in ssm:
    host = entry.getHost()
    headers = get_headers(entry.getRequest())
    host_user_agents[host] = host_user_agents[host] + list(set([a[1] for a in headers if a[0].lower() == 'user-agent' and a[1] not in host_user_agents[host]]))


# request types of in scope items
set([a.getRequest().split(b' ')[0].decode('utf8') for a in ssm])

# data

# URL parameters

# unusual request types (not GET, HEAD, POST)

# unusual headers





