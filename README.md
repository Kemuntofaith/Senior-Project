# **BACK TO SCHOOL APP BY MAIRURA FAITH KEMUNTO.** 
# SUPERVISOR: MR KEVIN MAYAKA
My app has 5 users:
1. App administrator
2. School administrators
3. Parents/students
4. Retailers
5. Students (coming soon)
6. Donors (coming soon)

## **PROJECT PROPOSAL**
## Background Information 
In Kenya, a majority of high school students are boarders travelling from various regions to stay 
at school for full academic terms. Each school opening period places a heavy logistical and 
financial burden on all shareholders. Parents put a lot of effort to ensure that their children 
have everything they need – from shopping for personal items, books and uniforms to paying 
school fees and arranging for transport. All these responsibilities and expenses coincide at the 
same time putting a lot of pressure on parents both financially and emotionally.  

Since most students study far from their homes, mostly in different cities or counties, they 
often face the physical challenge of travelling long distances with heavy luggage packed with 
their supplies for the entire term. It is not only tiring, but there is also the risk of misplacing 
items or forgetting to buy some essential items. Since most schools are located in rural and 
remote areas, finding forgotten or misplaced supplies nearby may be close to impossible. This 
forces students to travel back into the nearest towns to get the items or have to rely on 
someone to send whatever items they may have forgotten adding to the cost and 
inconvenience.  

Schools also face difficulties in enforcing their supply policies as students may knowingly or 
unknowingly carry restricted or excess items. Checking each student’s shopping manually takes 
time and is not always effective thus discipline and security concerns arise. There is also not a 
very clear system to communicate shopping requirements or changes thereof to parents ahead 
of time in a reliable and standardized way. 

Retailers and supermarkets feel the pressure of this period too. Since all back to school 
shopping happens within a short window, they struggle with demand fluctuations and 
expensive advertising campaigns that may not yield effective returns as even with all these 
efforts, not all parents know where the best deals are. Some end up spending more than 
necessary and retailers often struggle with stock levels because they cannot always accurately 
predict demand.  

Another issue that often goes unnoticed happens when students are done with school. Parents 
end up with numerous schools supplies that are still in good-condition that are no longer useful 
to them. Sadly, most of these items are either stored away or thrown out yet there are many 
students from low income homes who would greatly benefit from them. There is currently no 
structured way to connect those who need these items to those who have no use for them 
anymore. 

## Problem statement 
By now, I am sure you have realized that the current back to school process is financially and 
logistically stressful and inefficient for everyone involved. Parents bear the financial and 
emotional burden of ensuring their children’s needs are met, students endure long strenuous 
travel with heavy luggage and often lack access to forgotten or misplaced essential items due to 
the remote placement of many boarding schools, schools are often unable to effectively 
regulate what students bring and retailers struggle with unpredictable demand and inefficient 
advertising. Furthermore, usable school items are often discarded when they are no longer in 
use while needy students go without. There is a serious need for a system that can simplify, 
organize and support the entire experience while still encouraging sharing and responsible 
spending and that is where my app comes in.  

## Proposed system  
The proposed Back to School App is a centralized digital platform that connects parents, 
students, schools, retailers, and donors to simplify and organize the back-to-school process. 
Schools will upload required item lists, retailers will list products with prices, and parents can 
shop directly from nearby stores with delivery to schools. The app will also feature a savings 
wallet, price comparison, and donation options to reduce financial strain, ensure compliance 
with school policies, and support students from low-income families. 

## Objectives  
My main objective is to develop a system that will: 
1. Provide a centralized digital platform where schools, parents, students, retailers, and 
donors can interact and fulfill back-to-school requirements efficiently. 
2. Reduce financial stress on parents through gradual savings plans, price comparison 
tools, and access to affordable school supplies while simplifying student logistics by 
enabling online shopping with direct delivery of school supplies to schools. 
3. Assist schools in enforcing item compliance by listing allowed items and specifications 
on the platform and help retailers manage inventory and demand through real-time 
market insights and demand-driven supply.

## Tools and technologies 
1. Python Programming language  
 Will be used to develop both front end and backend. I will use the flask 
framework for backend APIs and Jinja2 for frontend rendering.  

2. MySQL  
 Will be used to create the database where I will store persistent data of all the 
users, products, schools, orders and wallets.  

3. Flask, Jinja2, 
 Flask will handle all HTTP routes, APIs, business logic, form processing and data 
exchange. 
 Jinja2 via flask will render dynamic HTML view and forms for user interaction 
 Flask backend, MySQL and Jinja2 will be used to support donation of money and 
the listing of second hand items 
 Flask, MySQL and Jinja2 will be used to allow parents or students to shop for 
supplies and submit orders for delivery 
 Flask-Login will secure the system and manage different user roles 

4. MySQL ORM  
 Mysql-connector-python will allow python scripts to interact with MySQL 
allowing me to save orders, fetch school requirements, validate compliance and 
calculate wallet balances.  

5. Python logic, MySQL (an M-Pesa API) 
 This will manage savings deposits, spending and transaction history 
 Will ensure that purchased items match school rules before order confirmation 

6. Python Query Logic and Jinja2 Table  
 This will display price ranges across retailers for each item.  

7. Flash messages and MySQL logs  
 will keep users informed about orders, compliance, donations and other 
notifications. 

## **CHALLENGES FACED**
1. I had a hard time with the text colors. once i managed to make some sections of text visible, other sections would suddenly become invisible and i couldn't figure out what was causing the problem
2. students are not able to personnally confirm that they received all the items they shopped for and they have to rely on the school administration to launch a complaint for them. its not very reliable but since kenyan schools do not allow students to access the school grounds with gadgets and there's not enoughcomputers in schools to cater for over 1000 students in good time, there is no way around it. 
3. There is a bit of a challenge when it comes to approvals where if users are not approved in the correct order, an error arises. 
4. Time constraints did not allow for the completion of all modules to work as expected.

## **FUTURE IMPROVEMENTS**
1. once i work out a way for students to access devices in the schools, a student module will be added to have the students confirm they received all the items they shopped for in the mean time i will add a complaints button for the school administration or parents to raise concerns on behalf of students. 
2. a donor module will be added where parents and well wishers may donate items, money, food and even vouchers to students and schools for the sake of providing for students without and ensuring that schools are able to sustain students while hopefully reducing cost for all parties. 

