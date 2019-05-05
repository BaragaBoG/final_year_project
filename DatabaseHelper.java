package com.example.toxicr0ak.chatapp;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import java.util.ArrayList;

public class DatabaseHelper extends SQLiteOpenHelper {

    public DatabaseHelper(Context context){
        super(context, "chatAppDB", null, 1);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("create table if not exists keyStorage (ID INTEGER PRIMARY KEY AUTOINCREMENT, RSAPriv BLOB, RSAPub BLOB, DHPriv BLOB, DHPub BLOB)");
        //
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS keyStorage");
        onCreate(db);
        //
    }

    boolean insertKeys(byte[] rsaPriv, byte[] rsaPub, byte[] dhPriv, byte[] dhPub){
        SQLiteDatabase db = this.getWritableDatabase();
        db.delete("keyStorage",null,null);
        System.out.println("db has been cleared");
        ContentValues contentValues = new ContentValues();
        contentValues.put("rsaPriv",rsaPriv);
        contentValues.put("rsaPub",rsaPub);
        contentValues.put("dhPriv",dhPriv);
        contentValues.put("dhPub",dhPub);
        long result = db.insert("keyStorage",null,contentValues);
        if (result == -1){
            return true;
        }
        else{
            return false;
        }
    }

    ArrayList<byte[]> extractSelfKeys(){
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor = db.rawQuery("select rsaPriv, dhPriv from keyStorage",null);
        byte[] rsaPriv = null;
        byte[] dhPriv = null;
        if (cursor.moveToFirst()){
            rsaPriv = cursor.getBlob(0);
            dhPriv = cursor.getBlob(1);
        }
        ArrayList<byte[]> arrayList = new ArrayList<>();
        arrayList.add(rsaPriv);
        arrayList.add(dhPriv);
        System.out.println("Selfkeys are: "+arrayList);
        return arrayList;
    }
}
