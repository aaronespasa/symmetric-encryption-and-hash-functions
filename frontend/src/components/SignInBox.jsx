const SignInBox = ({ children }) => {
  return (
    <div className="bg-green-100 flex items-center flex-col max-w-2xl mx-auto py-6 rounded-xl
                      shadow-sm">
        {children}
    </div>
  )
}

export default SignInBox