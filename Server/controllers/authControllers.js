import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';

export const register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.json({success: false, message: "Missing required fields"});
    }

    try {
        const existingUser = await userModel.findOne({ email });

        if (existingUser) {
            return res.json({success: false, message: "User already exists"});
        }

        // Hash the password before saving it to the database
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await userModel({name, email, password: hashedPassword});
        await user.save();

        // Generate a JWT token
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        //Sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Welcome to MERN Auth",
            text: `Hello ${name},\n\nThank you for registering with us! We are excited to have you on board.\n\nBest regards,\nThe Team`
        }

        await transporter.sendMail(mailOptions);

        return res.json({success: true, message: "Registration successful"});

    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}


export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({success: false, message: "Missing required fields"});
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({success: false, message: "User not found"});
        }

        // Compare the password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.json({success: false, message: "Invalid password"});
        }

        // Generate a JWT token
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        return res.json({success: true, message: "Login successful"});

    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}


export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });
        return res.json({success: true, message: "Logout successful"});
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

//Send Verification OTP to the user's email
export const sendVerifyOtp = async (req, res) => {
    try {
        const { userId } = req.body;

        const user = await userModel.findById(userId);

        if(user.isAccountVerified) {
            return res.json({success: false, message: "Account already verified"});
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generate a 6-digit OTP

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Verify your account",
            text: `Your verification OTP is ${otp}. It is valid for 10 minutes.`
        }
        await transporter.sendMail(mailOptions);

        res.json({success: true, message: "OTP sent to your email"});
        
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

// Verify OTP and activate the account
export const verifyEmail = async (req, res) => {
    const {userId, otp} = req.body;

    if (!userId || !otp) {
        return res.json({success: false, message: "Missing required fields"});
    }
    try {
        const user = await userModel.findById(userId);
        if (!user) {
            return res.json({success: false, message: "User not found"});
        }

        if (user.verifyOtp === '' || user.verifyOtp !== otp) {
            return res.json({success: false, message: "Invalid OTP"});
        }

        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({success: false, message: "OTP expired"});
        }

        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;

        await user.save();

        return res.json({success: true, message: "Account verified successfully"});

    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

// Check if the user is authenticated
export const isAuthenticated = async (req, res) => {
    try {
        return res.json({success: true, message: "User is authenticated"});

    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}