<h3>Sanitizer: Network Address Cleanup Tool</h3>
<p>Use <strong>Sanitizer</strong> to standardize and clean up various forms of network addresses from both command line and file input.</p>

<h4>Command Line Example:</h4>
<p>Input a string directly to the script that includes IP ranges, domain names, URLs, and CIDR blocks:</p>
<pre>python Sanitizer.py 5.5.1-3.1 hacking.cool http://test.com 23.23.23.0/29</pre>

<h4>Expected Output for Command Line Example:</h4>
<pre>
5.5.1.1
5.5.1.2
5.5.1.3
hacking.cool
test.com
23.23.23.1
23.23.23.2
23.23.23.3
23.23.23.4
23.23.23.5
23.23.23.6
</pre>

<h4>File Input Example:</h4>
<p>Consider a file named <em>addresses.txt</em> with mixed network identifiers:</p>
<pre>
5.5.5.0/29
host.com
testing.com
5.4.2.1
4.4.3-5.1-3
http://hacking.cool
9.9.9.9
</pre>

<h4>Command to Process File:</h4>
<pre>python sanitizer.py addresses.txt</pre>

<h4>Output for File Example:</h4>
<pre>
5.5.5.1
5.5.5.2
5.5.5.3
5.5.5.4
5.5.5.5
5.5.5.6
host.com
testing.com
5.4.2.1
4.4.3.1
4.4.3.2
4.4.3.3
4.4.4.1
4.4.4.2
4.4.4.3
4.4.5.1
4.4.5.2
4.4.5.3
hacking.cool
9.9.9.9
</pre>

<p>This detailed example guide provides clear instructions on how to use the <strong>Sanitizer</strong> tool effectively for network address standardization. It showcases the tool's versatility in handling various input formats and producing a clean uniform list of network addresses.</p>
