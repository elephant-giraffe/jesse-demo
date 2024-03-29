/*
 * This file is generated by jOOQ.
 */
package org.jesse.passkey.dbaccess.tables.records;


import java.time.LocalDateTime;
import org.jesse.passkey.dbaccess.tables.PasskeyDemo;
import org.jooq.Field;
import org.jooq.Record1;
import org.jooq.Record9;
import org.jooq.Row9;
import org.jooq.impl.UpdatableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({"all", "unchecked", "rawtypes"})
public class PasskeyDemoRecord extends UpdatableRecordImpl<PasskeyDemoRecord> implements
    Record9<String, String, String, String, String, String, String, LocalDateTime, LocalDateTime> {

    private static final long serialVersionUID = -170123146;

    /**
     * Setter for <code>jesse.passkey_demo.cred_id</code>.
     */
    public void setCredId(String value) {
        set(0, value);
    }

    /**
     * Getter for <code>jesse.passkey_demo.cred_id</code>.
     */
    public String getCredId() {
        return (String) get(0);
    }

    /**
     * Setter for <code>jesse.passkey_demo.user_handle</code>.
     */
    public void setUserHandle(String value) {
        set(1, value);
    }

    /**
     * Getter for <code>jesse.passkey_demo.user_handle</code>.
     */
    public String getUserHandle() {
        return (String) get(1);
    }

    /**
     * Setter for <code>jesse.passkey_demo.user_name</code>.
     */
    public void setUserName(String value) {
        set(2, value);
    }

    /**
     * Getter for <code>jesse.passkey_demo.user_name</code>.
     */
    public String getUserName() {
        return (String) get(2);
    }

    /**
     * Setter for <code>jesse.passkey_demo.pub_key</code>.
     */
    public void setPubKey(String value) {
        set(3, value);
    }

    /**
     * Getter for <code>jesse.passkey_demo.pub_key</code>.
     */
    public String getPubKey() {
        return (String) get(3);
    }

    /**
     * Setter for <code>jesse.passkey_demo.cred_type</code>.
     */
    public void setCredType(String value) {
        set(4, value);
    }

    /**
     * Getter for <code>jesse.passkey_demo.cred_type</code>.
     */
    public String getCredType() {
        return (String) get(4);
    }

    /**
     * Setter for <code>jesse.passkey_demo.transports</code>.
     */
    public void setTransports(String value) {
        set(5, value);
    }

    /**
     * Getter for <code>jesse.passkey_demo.transports</code>.
     */
    public String getTransports() {
        return (String) get(5);
    }

    /**
     * Setter for <code>jesse.passkey_demo.status</code>.
     */
    public void setStatus(String value) {
        set(6, value);
    }

    /**
     * Getter for <code>jesse.passkey_demo.status</code>.
     */
    public String getStatus() {
        return (String) get(6);
    }

    /**
     * Setter for <code>jesse.passkey_demo.create_time</code>.
     */
    public void setCreateTime(LocalDateTime value) {
        set(7, value);
    }

    /**
     * Getter for <code>jesse.passkey_demo.create_time</code>.
     */
    public LocalDateTime getCreateTime() {
        return (LocalDateTime) get(7);
    }

    /**
     * Setter for <code>jesse.passkey_demo.update_time</code>.
     */
    public void setUpdateTime(LocalDateTime value) {
        set(8, value);
    }

    /**
     * Getter for <code>jesse.passkey_demo.update_time</code>.
     */
    public LocalDateTime getUpdateTime() {
        return (LocalDateTime) get(8);
    }

    // -------------------------------------------------------------------------
    // Primary key information
    // -------------------------------------------------------------------------

    @Override
    public Record1<String> key() {
        return (Record1) super.key();
    }

    // -------------------------------------------------------------------------
    // Record9 type implementation
    // -------------------------------------------------------------------------

    @Override
    public Row9<String, String, String, String, String, String, String, LocalDateTime, LocalDateTime> fieldsRow() {
        return (Row9) super.fieldsRow();
    }

    @Override
    public Row9<String, String, String, String, String, String, String, LocalDateTime, LocalDateTime> valuesRow() {
        return (Row9) super.valuesRow();
    }

    @Override
    public Field<String> field1() {
        return PasskeyDemo.PASSKEY_DEMO.CRED_ID;
    }

    @Override
    public Field<String> field2() {
        return PasskeyDemo.PASSKEY_DEMO.USER_HANDLE;
    }

    @Override
    public Field<String> field3() {
        return PasskeyDemo.PASSKEY_DEMO.USER_NAME;
    }

    @Override
    public Field<String> field4() {
        return PasskeyDemo.PASSKEY_DEMO.PUB_KEY;
    }

    @Override
    public Field<String> field5() {
        return PasskeyDemo.PASSKEY_DEMO.CRED_TYPE;
    }

    @Override
    public Field<String> field6() {
        return PasskeyDemo.PASSKEY_DEMO.TRANSPORTS;
    }

    @Override
    public Field<String> field7() {
        return PasskeyDemo.PASSKEY_DEMO.STATUS;
    }

    @Override
    public Field<LocalDateTime> field8() {
        return PasskeyDemo.PASSKEY_DEMO.CREATE_TIME;
    }

    @Override
    public Field<LocalDateTime> field9() {
        return PasskeyDemo.PASSKEY_DEMO.UPDATE_TIME;
    }

    @Override
    public String component1() {
        return getCredId();
    }

    @Override
    public String component2() {
        return getUserHandle();
    }

    @Override
    public String component3() {
        return getUserName();
    }

    @Override
    public String component4() {
        return getPubKey();
    }

    @Override
    public String component5() {
        return getCredType();
    }

    @Override
    public String component6() {
        return getTransports();
    }

    @Override
    public String component7() {
        return getStatus();
    }

    @Override
    public LocalDateTime component8() {
        return getCreateTime();
    }

    @Override
    public LocalDateTime component9() {
        return getUpdateTime();
    }

    @Override
    public String value1() {
        return getCredId();
    }

    @Override
    public String value2() {
        return getUserHandle();
    }

    @Override
    public String value3() {
        return getUserName();
    }

    @Override
    public String value4() {
        return getPubKey();
    }

    @Override
    public String value5() {
        return getCredType();
    }

    @Override
    public String value6() {
        return getTransports();
    }

    @Override
    public String value7() {
        return getStatus();
    }

    @Override
    public LocalDateTime value8() {
        return getCreateTime();
    }

    @Override
    public LocalDateTime value9() {
        return getUpdateTime();
    }

    @Override
    public PasskeyDemoRecord value1(String value) {
        setCredId(value);
        return this;
    }

    @Override
    public PasskeyDemoRecord value2(String value) {
        setUserHandle(value);
        return this;
    }

    @Override
    public PasskeyDemoRecord value3(String value) {
        setUserName(value);
        return this;
    }

    @Override
    public PasskeyDemoRecord value4(String value) {
        setPubKey(value);
        return this;
    }

    @Override
    public PasskeyDemoRecord value5(String value) {
        setCredType(value);
        return this;
    }

    @Override
    public PasskeyDemoRecord value6(String value) {
        setTransports(value);
        return this;
    }

    @Override
    public PasskeyDemoRecord value7(String value) {
        setStatus(value);
        return this;
    }

    @Override
    public PasskeyDemoRecord value8(LocalDateTime value) {
        setCreateTime(value);
        return this;
    }

    @Override
    public PasskeyDemoRecord value9(LocalDateTime value) {
        setUpdateTime(value);
        return this;
    }

    @Override
    public PasskeyDemoRecord values(String value1, String value2, String value3, String value4, String value5, String value6, String value7,
        LocalDateTime value8, LocalDateTime value9) {
        value1(value1);
        value2(value2);
        value3(value3);
        value4(value4);
        value5(value5);
        value6(value6);
        value7(value7);
        value8(value8);
        value9(value9);
        return this;
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached PasskeyDemoRecord
     */
    public PasskeyDemoRecord() {
        super(PasskeyDemo.PASSKEY_DEMO);
    }

    /**
     * Create a detached, initialised PasskeyDemoRecord
     */
    public PasskeyDemoRecord(String credId, String userHandle, String userName, String pubKey, String credType, String transports, String status,
        LocalDateTime createTime, LocalDateTime updateTime) {
        super(PasskeyDemo.PASSKEY_DEMO);

        set(0, credId);
        set(1, userHandle);
        set(2, userName);
        set(3, pubKey);
        set(4, credType);
        set(5, transports);
        set(6, status);
        set(7, createTime);
        set(8, updateTime);
    }

}
