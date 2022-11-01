import { useState } from "react"
import { Link } from 'react-router-dom'
import SignInBox from "../components/SignInBox"
import ErrorMessage from "../components/ErrorMessage"

const Login = () => {
  const [errorMessage, setErrorMessage] = useState(null)

  return (
    <SignInBox>
        <h1 className="text-3xl font-bold mb-6">Iniciar Sesión</h1>
        <form className="mb-6" method="POST">
            <input className="block w-full py-1 px-2 outline-none" type="text" name="username" id="username" placeholder="Nombre de usuario" />
            <input className="block w-full py-1 px-2 my-2 outline-none" type="password" name="password" id="password" placeholder="Contraseña" />
            {errorMessage && <ErrorMessage message={errorMessage} />}
            <button className="bg-blue-400 text-white py-2 px-20 hover:bg-blue-300 transition-colors " type="submit">Registrarse</button>
        </form>
        <div>¿No tienes cuenta? &nbsp;
            <Link className="font-bold text-blue-500 hover:text-blue-400" to="/signup">Registrarse</Link>
        </div>
    </SignInBox>
  )
}

export default Login