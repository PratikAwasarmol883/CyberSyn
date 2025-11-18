from dns import resolver

def is_valid_domain(sub):
    try:
        resolver.resolve(sub, "A")   # Correct function
        return True
    except:
        return False
