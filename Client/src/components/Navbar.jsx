import React from 'react';
import { assets } from '../assets/assets';

const Navbar = () => {
  return (
    <div className='w-full flex justify-between items-center p-4 sm:p-6 sm:px-24 absolute top-0'>
        <img src={assets.logo} alt="" className='w-28 sm:w-32'/>
        <button>Login</button>
    </div>
  )
}

export default Navbar;