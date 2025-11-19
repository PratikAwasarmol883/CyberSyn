from fastapi import FastAPI
from router.domain_discovery import domainRouter

app = FastAPI()

app.include_router(domainRouter,tags=["Domain Discovery"])


