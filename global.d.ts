// global.d.ts
declare module "bcryptjs";
declare module "passport";
declare module "passport-local";
declare module "passport-jwt";
declare module "multer";
declare module "cors";
declare module "compression";
declare module "morgan";
declare module "uuid";
declare module "swagger-ui-express";
declare module "swagger-jsdoc";
declare module "pdfkit";

// حل مشكلة multer.Request.file
declare namespace Express {
  export interface Request {
    file?: Multer.File;
    files?: Multer.File[];
  }
}