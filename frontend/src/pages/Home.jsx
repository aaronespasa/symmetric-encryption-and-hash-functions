import { Link } from "react-router-dom"

const Home = () => {
  return (
    <div>
      <h1 className="text-3xl font-bold ">
          Bienvenido a tu servicio de sanidad privada.
      </h1>
      <h2 className="mt-4">
          Inicie sesión o registrese para poder accedera su receta médica.
      </h2>
      <div className="flex items-center mt-10">
          <Link className="mr-6 bg-blue-500 py-2 px-4 rounded-md hover:bg-blue-400 transition-colors text-white" to="/login">Iniciar Sesión</Link>
          <Link className="mr-6 bg-blue-500 py-2 px-4 rounded-md hover:bg-blue-400 transition-colors text-white" to="/signup">Registrarse</Link>
      </div>
    </div>
  )
}

export default Home