# BurpPythonGateway

Uses py4j to make Burp Extender internals available to Python code and interactive interpreters like iPython


# What?

Using this extension allows you to get at things in your Burp session, such as the Site Map, or the contents of requests and responses in the Proxy History, from Python. This could be in a Python script, or within an interactive Python session like iPython or Jupyter Notebook.

# How?

You need to install the [py4j](https://www.py4j.org/) module in your Python install, and build and load this extension into Burp.

You can install py4j for Python using pip

    pip install py4j


Then, the following code executed in Python will give you access to everything from the [IBurpExtenderCallbacks](https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html) interface via the `callbacks` Python variable.


    from py4j.java_gateway import JavaGateway
    gateway = JavaGateway()
    callbacks = gateway.entry_point


With this `callbacks` variable, you can do all sorts of stuff. Including potentially get yourself into trouble, but I'm assuming you're an adult and will read the [api documentation](https://portswigger.net/burp/extender/api/index.html) before running things like `callbacks.exitSuite()`.


# What can you do with this exactly?

Anything that the [IBurpExtenderCallbacks](https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html) interface allows you to do.

You can explore the functionality exposed by the `callbacks` object using Python introspection (e.g. `dir`, or completion in Python editors or iPython) to see the options available to you. 

The idea is to provide programmatic access to the contents of a Burp session in order to allow you to perform complex analysis without requiring a specific extension to be written for each task. I do most of my ad hoc analysis during assessments in iPython so this gives me the ability to directly access my Burp session information from the same interface.

To get you thinking, here are some simple specific examples.

## Examples

You can get the proxy history at the current point in time:

    proxyhistory = callbacks.getProxyHistory()
    

You can then get the contents of the request and response for a particular numbered entry `no` in the proxy history

    no = 1
    entry = proxyhistory[no-1]


Get the raw request and response from that entry

    response = entry.getResponse()
    request = entry.getRequest()


Or get more specific information about that request

    url = entry.getUrl()
    host = entry.getHost()
    port = entry.getPort()


For more complex analysis, get an [IExtensionHelpers](https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html) object as `helpers`, and use that to analyse your proxy history entry

    helpers = callbacks.getHelpers()
    analysis = helpers.analyzeRequest(entry)
    headers = analysis.getHeaders()
    method = analysis.getMethod()
    


You can also get the site map

    sitemap = callbacks.getSiteMap('')


And query the items in the site map that are in scope

    inscope = [a for a in sitemap if callbacks.isInScope(a.getUrl())]


Whatever else you want to do is only limited by your imagination (and Python coding ability).


# Hints and tips

If the information you get back using this extension does not look like you expect it to in your Python output, you can try a few things to try and interpret it in a way that might make more sense.


Explicitly convert the object to a string

    In [66]: entry.getUrl()
    Out[66]: JavaObject id=o59138

    In [67]: str(entry.getUrl())
    Out[67]: 'http://detectportal.firefox.com:80/success.txt?ipv4'


Use `dir` to see if the variable has methods you might need to call

    In [70]: dir(entry.getUrl())
    Out[70]:
    ['equals',
     'getAuthority',
     'getClass',
     'getContent',
     'getDefaultPort',
     'getFile',
     'getHost',
     'getPath',
     'getPort',
     'getProtocol',
     'getQuery',
     'getRef',
     'getUserInfo',
     'hashCode',
     'notify',
     'notifyAll',
     'openConnection',
     'openStream',
     'sameFile',
     'setURLStreamHandlerFactory',
     'toExternalForm',
     'toString',
     'toURI',
     'wait']
     
    In [71]: entry.getUrl().toString()
    Out[71]: 'http://detectportal.firefox.com:80/success.txt?ipv4'


Use `type` to get a hint about how the variable might need to be dealt with


    In [73]: callbacks.getBurpVersion()
    Out[73]: JavaObject id=o59150

    In [74]: type(callbacks.getBurpVersion())
    Out[74]: py4j.java_collections.JavaArray

    In [75]: list(callbacks.getBurpVersion())
    Out[75]: ['Burp Suite Professional', '2022', '1.1']



# Building the Burp extension

You can build the .jar version of the extension to load into Burp using the following command. 

    mvn clean package

The compiled extension file will be created under `target/` - the jar file with `-with-dependencies` in the name is the one you load into Burp.
