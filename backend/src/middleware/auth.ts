import { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import User from "../models/user";

declare global {
  namespace Express {
    interface Request {
      userId: string;
      userEmail: string;
    }
  }
}

const verifyToken = async (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies["auth_token"];
  if (!token) {
      return res.status(401).json({ message: "unauthorized" });
  }

  try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY as string) as JwtPayload;
      const user = await User.findById(decoded.userId);
      if (!user) {
          return res.status(401).json({ message: "unauthorized" });
      }
      req.userId = user.id;
      req.userEmail = user.email;
      next();
  } catch (error) {
      return res.status(401).json({ message: "unauthorized" });
  }
};

export default verifyToken;