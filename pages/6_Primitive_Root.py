import streamlit as st

st.divider()
st.header("Primitive Root")
st.snow()
st.text('by Selwyn Kent Oñedo')
st.divider()

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def primitive_check(g, p):
    primitive_roots = []
    for i in range(1, p):
        temp = set()
        output = ''
        for j in range(1, p):
            res = pow(i, j, p)
            output += f"{i}^{j} mod {p} = {res}"
            if j < p - 1:
                output += ", "
            temp.add(res)
            if res == 1:
                break
        if len(temp) == p - 1:
            primitive_roots.append(i)
            output += f" ==> {i} is a primitive root of {p}, "
        st.write(output)
    return primitive_roots

def display_result(q, g):
    if is_prime(q):
        primitive_roots = primitive_check(g, q)
        if g in primitive_roots:
            st.write(f"{g} is a primitive root of {q} - List of Primitive roots: {primitive_roots}")
        else:
            st.write(f"{g} is NOT a primitive root of {q} - List of Primitive roots: {primitive_roots}")
    else:
        st.write(f"{q} is not a prime number!!")

q = st.text_input("Number 1")
g = st.text_input("Number 2")

if st.button("Submit"):
    try:
        q = int(q)
        g = int(g)
        display_result(q, g)
    except ValueError:
        st.write("Please enter valid integers for both numbers.")
    st.balloons()

st.divider()    