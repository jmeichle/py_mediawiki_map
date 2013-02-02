#!/usr/bin/python
import pydot

#	 finds and reports on link strutures of a mediawiki
#		written by John Meichle, 5/14/12
#		License: GPLv2

import optparse, sys, string, random

import mwclient

parser = optparse.OptionParser("usage: %prog [options]\nWritten by: John Meichle\n\tGPLv2")

#wipe wiki
parser.add_option("-e", "--erase", dest="clearWiki", 
		  action="store_true", help="Whether to clear the target wiki")

#randomize whatevers being built
parser.add_option("-r", "--randomize", dest="randomizeNames", 
		  action="store_true", help="Randomize Wiki Page Names")

#build wiki from dot data
parser.add_option("-w", "--buildwiki", dest="buildWiki", 
		  action="store_true", help="Build Wiki with given .dot file")

#build dot from wiki data
parser.add_option("-d", "--builddot", dest="buildDot", 
		  action="store_true", help="Build DOT file from Wiki")

parser.add_option("-S", "--ssl", dest="useSSL",
		  action="store_true", help="Use SSL for connection (https)")

#save dot for created stuff
parser.add_option("-D", "--savedot", dest="saveDot", 
		  type="string", help="Save DOT file from resulting wiki, aka randomized input DOT")

#stealthy mode
parser.add_option("-s", "--stealthy", dest="stealhy", 
		  action="store_true", help="Build Wiki links as spaces.")

# wiki options
parser.add_option("-H", "--host", dest="host",
                  type="string", help="Host of target wiki")

parser.add_option("-P", "--path", dest="path",
                  type="string", help="Path to the target wiki")

parser.add_option("-u", "--username", dest="username",
                  type="string", help="Username for the target wiki")

parser.add_option("-p", "--password", dest="password",
                  type="string", help="Password for the target wiki")

parser.add_option("-x", "--domain", dest="domain",
                  type="string", help="domain for the target wiki user")

#dot file to use
parser.add_option("-f", "--dotfile", dest="dotfile",
		  type="string", help="DOT file to be used")

#list stuff
parser.add_option("-l", "--list", dest="listNodesInDot", 
		  action="store_true", help="list all Nodes In Dot File")



(options, args) = parser.parse_args()

if len(sys.argv) == 1:
	print "Run with -h to see options"
	sys.exit(1)

edgeList = []
nodeList = []
global site

def setupWikiConnect(username,password,domain,host,path):
	#print "Connecting to Wiki....",
	global site
	if options.useSSL:
		print "Using SSL"
		site = mwclient.Site(("https",unicode(host)), path=unicode(path), do_init=False)
	else:
		print "No SSL"
		site = mwclient.Site(unicode(host), path=unicode(path), do_init=False)		
	if domain == None:
		print "NOT Using domain"
		print "site.login(unicode(username),unicode(password))"
		site.login(unicode(username),unicode(password))
	else:
		print "Using domain"
		print "site.login(username=unicode(username),password=unicode(password),domain=unicode(domain))"
		site.login(username=unicode(username),password=unicode(password),domain=unicode(domain))
	#print " Done!"
	site.site_init()

def eraseWiki():
	if site:
	#	print "Clearing Wiki.....",
		for page in site.allpages():
			page.delete()
	#	print " Done!"

def buildWiki():
	print "Building Wiki...."
	createdSrc = []
	createdDst = []
	if not options.randomizeNames:
		for page in nodeList:
			print "\tCreating Node: " + page
			page = site.Pages[page]
			text = page.edit()
			page.save(text +  u'.')	
		for edge in edgeList:
			print "\tCreating Edge: " + edge[0] + " -> " + edge[1]
			page = site.Pages[edge[0]]
			text = page.edit()
			if options.stealhy:
				page.save(text + unicode("[[" + edge[1] + "| ]]"))
			else:
				page.save(text + unicode("[[" + edge[1] + "]]"))	
		if options.saveDot:
			buildDot()
	else:
		for page in rNodeList:
			print "\tCreating Node: " + page
			page = site.Pages[page]
			text = page.edit()
			page.save(text +  u'.')	
		for edge in rEdgeList:
			print "\tCreating Edge: " + edge[0] + " -> " + edge[1]
			page = site.Pages[edge[0]]
			text = page.edit()
			if options.stealhy:
				page.save(text + unicode("[[" + edge[1] + "| ]]"))
			else:
				page.save(text + unicode("[[" + edge[1] + "]]"))	
		if options.saveDot:
			buildRDot()
	print "Done!"
	displayImportantNodes()

def displayImportantNodes():
	if options.randomizeNames:
		print "STA: " + rHashList.get('STA')
		print "FIN: " + rHashList.get('FIN')	
	else:
		print "STA"
		print "FIN"

def buildDot():
	#print "Building Wiki...."
	newGraph = pydot.Dot(graph_type='digraph')
	for edge in edgeList:
		graphEdge = pydot.Edge(edge[0], edge[1])
		newGraph.add_edge(graphEdge)
	if options.saveDot:
		newGraph.write_raw(options.saveDot)
	else:
		print newGraph.to_string()


def buildRDot():
	#print "Building Wiki...."
	newGraph = pydot.Dot(graph_type='digraph')
	for edge in rEdgeList:
		graphEdge = pydot.Edge(edge[0], edge[1])
		newGraph.add_edge(graphEdge)
	if options.saveDot:
		newGraph.write_raw(options.saveDot)
	else:
		print newGraph.to_string()

#.replace('\"','')

def loadDotFile(dotfile):
	dotGraph = pydot.graph_from_dot_file(dotfile)
	graphEdges = dotGraph.get_edges()
	for edge in graphEdges:
		edgeList.append( (str(edge.get_source().replace('\"','')), edge.get_destination().replace('\"','')) )
		if edge.get_source().replace('\"','') not in nodeList:
			nodeList.append(edge.get_source().replace('\"',''))
		if edge.get_destination().replace('\"','') not in nodeList:
			nodeList.append(edge.get_destination().replace('\"',''))

#		edgeList.append( (str(edge.get_source()[1:-1]), edge.get_destination()[1:-1]) )
#		if edge.get_source()[1:-1] not in nodeList:
#			nodeList.append(edge.get_source()[1:-1])
#		if edge.get_destination()[1:-1] not in nodeList:
#			nodeList.append(edge.get_destination()[1:-1])
	nodeList.sort()

def loadWikiData():
#	print "Loading Wiki's Data..... ",
	for page in site.allpages():
    	#	print "Node Detected: %s" % page.name
		nodeList.append(page.name)
		for outlink in page.links():
	#		print "\tLink To: %s" % outlink.name
			edgeList.append((page.name, outlink.name))
		#nodeList.append(page.name)
	#for edge in site.alllinks():
#		print edge.links()
	#print "Done!"


def listNodes():
	for node in nodeList:
		print node

def listEdges():
	for node in edgeList:
		print "%s -> %s" % ( node[0], node[1] )

def listRNodes():
	for node in rNodeList:
		print node

def listREdges():
	for node in rEdgeList:
		print "%s -> %s" % ( node[0], node[1] )

rHashList = {}
rNodeList = []
rEdgeList = []

def randomizeLists():
	for name in nodeList:
		if name not in rNodeList:
			while True:
				newName = randomName()
				if not rHashList.has_key(newName):
					rHashList.update({name:newName})
					rNodeList.append(newName)
					break				
	for edge in edgeList:
		if not rHashList.has_key(edge[1]):
			newName2 = randomName()
			rHashList.update({edge[1]:newName2})
		rEdgeList.append( ( rHashList[edge[0]], rHashList[edge[1]] ) )

def randomName(size=8, chars=string.ascii_uppercase + string.digits):
	return ''.join(random.choice(chars) for x in range(size))

def main():
	if options.listNodesInDot:
		if not options.dotfile:
			setupWikiConnect( options.username, options.password, options.domain, options.host, options.path)
			loadWikiData()
			if options.randomizeNames:
				randomizeLists()
				print "----- Nodes: ------"			
				listRNodes()
				print "----- Edges: ------"
				listREdges()
			else:
				print "----- Nodes: ------"			
				listNodes()
				print "----- Edges: ------"
				listEdges()
		else:
			loadDotFile(options.dotfile)
			if options.randomizeNames:
				randomizeLists()
				print "----- Nodes: ------"			
				listRNodes()
				print "----- Edges: ------"
				listREdges()
			else:
				print "----- Nodes: ------"			
				listNodes()
				print "----- Edges: ------"
				listEdges()
		sys.exit(0)
	setupWikiConnect( options.username, options.password, options.domain, options.host, options.path)
	if options.clearWiki:
		eraseWiki()
	if options.buildWiki:
		if not options.dotfile:
			print "Error: Need to specify .dot file with -D"
		else:
			loadDotFile(options.dotfile)
			if options.randomizeNames:
				 randomizeLists()
			buildWiki()	
	elif options.buildDot:
		loadWikiData()
		buildDot()
	sys.exit(1)

if __name__ == '__main__':
	main()
