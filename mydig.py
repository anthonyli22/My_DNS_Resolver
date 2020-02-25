#!/usr/bin/env python

from __future__ import print_function

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import time
import sys
import datetime

#code assumes that there will be at least one A type under additional or that there
#is no lines after additional, don't know if that matters

def mydig(domain):
    domain = str(domain) #might be unnecessary

    zname = dns.name.from_text(domain)
    z = dns.message.make_query(zname, dns.rdatatype.A) #starts query
    response = dns.query.udp(z, "198.41.0.4") #root server = 198.41.0.4

    #print("reponse")
    #print(response)

    a = response.to_text().splitlines() # splits the response into multiple string objects and puts them into an array
    ansIndex = a.index(";ANSWER") #location of answer in array
    authIndex = a.index(";AUTHORITY")  #location of authority in array
    addIndex = a.index(";ADDITIONAL") #location of additional in array

    if (a[ansIndex + 1].__eq__(";AUTHORITY")): #when there isn't anything in the answer section
        if(response.to_text().endswith(";ADDITIONAL")): #when there isn't anything in the additional section
            if(a[authIndex+1].__eq__(";ADDITIONAL")): # if all 3 sections are empty
                print("Site does not exist 1")
            else:
                nexLine = a[authIndex + 1] #takes the next line under authority
                nexLineSplit = nexLine.split(" ") # splits so that i can take last part of the line
                if (nexLineSplit[3].__eq__("NS")):  # if NS then I run mydig again
                    mydigHelper(nexLineSplit[4], "198.41.0.4", domain)

        else:
            nextLineIndex = 1 # help iterate through lines under additional section
            loopCount = 0 #loop counter
            while(loopCount == 0): # if all are AAAA then indexOutOfBound error
                line = a[addIndex+nextLineIndex]
                line = line.split(" ") #takes the IP address
                if(line[3] == "A"):
                    mydigHelper(domain,line[4],domain) # uses the new IP add found for mydig
                    loopCount = 1 #stops the loop
                nextLineIndex = nextLineIndex + 1 #iterator
    else:
        #when something appears under answer section
        nexLine = a[ansIndex+1]
        nexLineSplit = nexLine.split(" ")
        if(nexLineSplit[3].__eq__("CNAME")): #bonus part, turns CNAME into IP add by running mydig
            mydigHelper(nexLineSplit[4], "198.41.0.4",domain)
        else:
            print("QUESTION:")
            questionIndex = a.index(";QUESTION")
            print(a[questionIndex+1]) #prints out question
            print("ANSWER:")
            print(a[ansIndex+1])

def mydigHelper(domain, ip_add, og_dom):
    #print(ip_add)
    domain = str(domain) #might be unnecessary

    zname = dns.name.from_text(domain)
    z = dns.message.make_query(zname, dns.rdatatype.A) #starts query, type A's
    response = dns.query.udp(z, ip_add) #root server = 198.41.0.4
    #print("RESPONSE")
    #print(response)

    a = response.to_text().splitlines() #splits response into array by lines
    ansIndex = a.index(";ANSWER")
    authIndex = a.index(";AUTHORITY")
    addIndex = a.index(";ADDITIONAL")

    if (a[ansIndex + 1].__eq__(";AUTHORITY")): #if there is no answers found yet
        if(response.to_text().endswith(";ADDITIONAL")): #if there is nothing in additional section
            if(a[authIndex+1].__eq__(";ADDITIONAL")): # if there is nothing in authority section
                print("Site does not exist 2")
            else:
                line = a[authIndex + 1]
                line = line.split(" ")
                if(line[3].__eq__("NS")): #if answer is NS resolve again using root server
                    mydigHelper(line[4], '198.41.0.4', og_dom)
                elif(line[3].__eq__("CNAME")): #if answer if CNAME resolve with previous IP_address
                    mydigHelper(line[4], ip_add, og_dom)
                else:
                    print("QUESTIONS:")
                    questionIndex = a.index(";QUESTION")
                    print(a[questionIndex + 1])  # prints out question
                    print("ANSWER:")
                    print(a[authIndex + 1])
        else:
            nextLineIndex = 1 #used to find next line in additional
            loopCount = 0 #loop counter
            while(loopCount == 0): #
                g = a[addIndex+nextLineIndex]
                g = g.split(" ")
                if(g[3] == "A"): #if A then run mydig on that IP_address
                    mydigHelper(domain,g[4], og_dom)
                    loopCount = 1
                nextLineIndex = nextLineIndex + 1
    else:
        nexLine = a[ansIndex+1]
        nexLineSplit = nexLine.split(" ")
        if(nexLineSplit[3].__eq__("CNAME")): #bonus part, turn CNAME to IP_address by running mydig with new domain and root sever IP
            mydigHelper(nexLineSplit[4], "198.41.0.4", og_dom)
        else:
            print("QUESTION:")
            questionIndex = a.index(";QUESTION")
            question = a[questionIndex+1]
            ques = question.find(" ")
            ques = question[ques:]
            ques = og_dom + ques
            print(ques) #prints out question
            print("ANSWER:")
            print(a[ansIndex+1])

if __name__ == '__main__':
    dns_start = time.time() #starts timer
    #mydig("www.wikipedia.org")
    mydig(sys.argv[1]) # works for google
    print("Query Time: "+ str((time.time() - dns_start) * 1000))
    print("When: " + str(datetime.datetime.today()))