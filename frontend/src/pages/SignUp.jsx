import { useState } from "react"
import { Link, useNavigate } from 'react-router-dom'
import SignInBox from "../components/SignInBox"
import ErrorMessage from "../components/ErrorMessage"

function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

const SignUp = () => {
  const [errorMessage, setErrorMessage] = useState(null)
  const [formData, setFormData] = useState({
    username: "",
    password: ""
  })

  const csrftoken = getCookie('csrftoken');

  const navigate = useNavigate()

  const { username, password } = formData

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    try {
      const response = await fetch("http://localhost:8000/signup/new", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrftoken
        },
        body: JSON.stringify(formData)
      })
      const data = await response.json()
      if (data.error) {
        setErrorMessage(data.error)
      }
      else {
        navigate("/login")
      }
    } catch (error) {
      console.error(error)
    }
  }

  return (
    <SignInBox>
        <h1 className="text-3xl font-bold mb-6">Registrarse</h1>
        <div className="max-w-md mt-4 mb-10">
            <p className="mb-4">Para guardar la contraseña, se genera un hash utilizando el algoritmo de SHA256 y ese hash se cifra utilizando AES</p>
            <p>Ten en cuenta que tu contraseña deberá tener:</p>
            <p> - Al menos 8 caracteres</p>
            <p> - Al menos 1 número</p>
            <p> - Al menos 1 letra mayúscula</p>
            <p> - Al menos 1 letra minúscula</p>
            <p> - Al menos 1 caracter especial</p>
        </div>
        <form className="mb-6" method="POST" onSubmit={e => handleSubmit(e)}>
            <input className="block w-full py-1 px-2 outline-none" type="text" name="username" id="username" placeholder="Nombre de usuario"
                onChange={e => handleChange(e)} />
            <input className="block w-full py-1 px-2 my-2 outline-none" type="password" name="password" id="password" placeholder="Contraseña"
                onChange={e => handleChange(e)} />
            <input className="block w-full py-1 px-2 my-2 outline-none" type="password" name="password" id="password" placeholder="Contraseña de nuevo" />
            {errorMessage && <ErrorMessage message={errorMessage} />}
            <button className="bg-blue-400 text-white py-2 px-20 hover:bg-blue-300 transition-colors " type="submit">Registrarse</button>
        </form>
        <div>¿Ya tienes cuenta? &nbsp;
            <Link className="font-bold text-blue-500 hover:text-blue-400" to="/login">Inicia Sesión</Link>
        </div>
    </SignInBox>
  )
}

export default SignUp