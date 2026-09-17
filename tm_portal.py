#!/usr/bin/env python3
from pytm.pytm import TM, Server, Datastore, Dataflow, Actor, Boundary

tm = TM("Web Portal")
tm.description = "Level 1 DFD of a web portal"
tm.isOrdered = True

internet = Boundary("Internet")
portal = Boundary("Web Portal")
payment_zone = Boundary("Payment Provider")

user = Actor("User")
user.inBoundary = internet

content_creator = Actor("Content Creator")
content_creator.inBoundary = internet

frontend = Server("Frontend (static files)")
frontend.inBoundary = portal

backend = Server("Application Backend")
backend.inBoundary = portal

db = Datastore("Database")
db.inBoundary = portal

payment = Server("Payment Service")
payment.inBoundary = payment_zone

user_to_frontend = Dataflow(user, frontend, "Request page / static assets")
frontend_to_user = Dataflow(frontend, user, "HTML/CSS/JS")

user_to_backend = Dataflow(user, backend, "API request (browse, checkout)")
backend_to_user = Dataflow(backend, user, "API response")

creator_to_backend = Dataflow(content_creator, backend, "Create/update content")
backend_to_creator = Dataflow(backend, content_creator, "Save confirmation")

backend_to_db = Dataflow(backend, db, "Read/write query")
db_to_backend = Dataflow(db, backend, "Query result")

backend_to_payment = Dataflow(backend, payment, "Charge request")
payment_to_backend = Dataflow(payment, backend, "Charge result")

tm.process()
