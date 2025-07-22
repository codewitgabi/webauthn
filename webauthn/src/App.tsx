import Login from "./components/login";
import Register from "./components/register";

function App() {
  return (
    <>
      <h1 className="border border-teal-300 p-4 px-8 rounded-full text-center w-max mx-auto mt-4 text-lg font-semibold">
        WebAuthn (Biometric authentication)
      </h1>

      <div className="mt-12 w-[800px] mx-auto grid grid-cols-2 gap-4">
        <Register />
        <Login />
      </div>
    </>
  );
}

export default App;
