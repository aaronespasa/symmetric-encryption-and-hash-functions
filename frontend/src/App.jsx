import {
  BrowserRouter as Router,
  Outlet,
  Routes,
  Route
} from 'react-router-dom'

import Layout from "./components/Layout"
import Navbar from "./components/Navbar"
import Footer from "./components/Footer"
import Home from "./pages/Home"
import Login from "./pages/Login"
import SignUp from "./pages/SignUp"
import Prescription from './pages/Prescription'

const App = () => {
  return (
    <Router>
      <Layout>
        <Navbar />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<SignUp />} />
          <Route path="/receta/:userId" element={<Prescription />} />
          <Route path="*" element={<p>No hemos encontrado la página</p>} />
        </Routes>
      </Layout>
      <Footer />
    </Router>
  )
}

export default App
