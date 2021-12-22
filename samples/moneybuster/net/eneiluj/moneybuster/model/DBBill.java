package net.eneiluj.moneybuster.model;

import android.util.Log;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class DBBill implements Item, Serializable {

    // key_id, key_remoteId, key_projectid, key_payer_remoteId, key_amount, key_date, key_what
    private long id;
    private long remoteId;
    private long projectId;
    private long payerId;
    private double amount;
    private long timestamp;
    private String what;
    private String comment;
    // OK, ADDED, EDITED, DELETED
    private int state;

    private String repeat;
    private String paymentMode;
    private int paymentModeRemoteId;
    public static final String PAYMODE_NONE = "n";
    public static final String PAYMODE_CARD = "c";
    public static final String PAYMODE_CASH = "b";
    public static final String PAYMODE_CHECK = "f";
    public static final String PAYMODE_TRANSFER = "t";
    public static final String PAYMODE_ONLINE_SERVICE = "o";

    public static final int PAYMODE_ID_NONE = 0;
    public static final int PAYMODE_ID_CARD = -1;
    public static final int PAYMODE_ID_CASH = -2;
    public static final int PAYMODE_ID_CHECK = -3;
    public static final int PAYMODE_ID_TRANSFER = -4;
    public static final int PAYMODE_ID_ONLINE_SERVICE = -5;

    public static final Map<String, Integer> oldPmIdToNew = new HashMap<String, Integer>() {{
        put(PAYMODE_NONE, PAYMODE_ID_NONE);
        put(PAYMODE_CARD, PAYMODE_ID_CARD);
        put(PAYMODE_CASH, PAYMODE_ID_CASH);
        put(PAYMODE_CHECK, PAYMODE_ID_CHECK);
        put(PAYMODE_TRANSFER, PAYMODE_ID_TRANSFER);
        put(PAYMODE_ONLINE_SERVICE, PAYMODE_ID_ONLINE_SERVICE);
    }};

    public static final Map<Integer, String> newPmIdToOld = new HashMap<Integer, String>() {{
        put(PAYMODE_ID_NONE, PAYMODE_NONE);
        put(PAYMODE_ID_CARD, PAYMODE_CARD);
        put(PAYMODE_ID_CASH, PAYMODE_CASH);
        put(PAYMODE_ID_CHECK, PAYMODE_CHECK);
        put(PAYMODE_ID_TRANSFER, PAYMODE_TRANSFER);
        put(PAYMODE_ID_ONLINE_SERVICE, PAYMODE_ONLINE_SERVICE);
    }};

    private int categoryRemoteId;
    public static final int CATEGORY_NONE = 0;
    public static final int CATEGORY_GROCERIES = -1;
    public static final int CATEGORY_LEISURE = -2;
    public static final int CATEGORY_RENT= -3;
    public static final int CATEGORY_BILLS = -4;
    public static final int CATEGORY_CULTURE = -5;
    public static final int CATEGORY_HEALTH = -6;
    public static final int CATEGORY_SHOPPING = -10;
    public static final int CATEGORY_REIMBURSEMENT = -11;
    public static final int CATEGORY_RESTAURANT = -12;
    public static final int CATEGORY_ACCOMODATION = -13;
    public static final int CATEGORY_TRANSPORT = -14;
    public static final int CATEGORY_SPORT = -15;

    private List<DBBillOwer> billOwers;

    public static final int STATE_OK = 0;
    public static final int STATE_ADDED = 1;
    public static final int STATE_EDITED = 2;
    public static final int STATE_DELETED = 3;

    public static final String NON_REPEATED = "n";

    public DBBill(long id, long remoteId, long projectId, long payerId, double amount,
                  long timestamp, String what, int state, String repeat,
                  String paymentMode, int categoryRemoteId,
                  String comment, int paymentModeRemoteId) {
        this.id = id;
        this.remoteId = remoteId;
        this.projectId = projectId;
        this.payerId = payerId;
        this.amount = amount;
        this.timestamp = timestamp;
        this.what = what;
        this.repeat = repeat;
        this.paymentMode = paymentMode;
        this.paymentModeRemoteId = paymentModeRemoteId;
        this.categoryRemoteId = categoryRemoteId;
        this.comment = comment;

        this.billOwers = new ArrayList<>();

        this.state = state;
    }

    public List<Long> getBillOwersIds() {
        List<Long> result = new ArrayList<>();
        for (DBBillOwer bo : billOwers) {
            result.add(bo.getMemberId());
        }
        return result;
    }

    public int getState() {
        return state;
    }

    public void setState(int state) {
        this.state = state;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public List<DBBillOwer> getBillOwers() {
        return billOwers;
    }

    public void setBillOwers(List<DBBillOwer> billOwers) {
        this.billOwers = billOwers;
    }

    public long getRemoteId() {
        return remoteId;
    }

    public void setRemoteId(long remoteId) {
        this.remoteId = remoteId;
    }

    public long getProjectId() {
        return projectId;
    }

    public void setProjectId(long projectId) {
        this.projectId = projectId;
    }

    public long getPayerId() {
        return payerId;
    }

    public void setPayerId(long payerId) {
        this.payerId = payerId;
    }

    public double getAmount() {
        return amount;
    }

    public void setAmount(double amount) {
        this.amount = amount;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public String getDate() {
        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(timestamp * 1000);
        Log.v("ll", "["+what+"] get date ts "+timestamp+" year "+cal.get(Calendar.YEAR));
        int month = cal.get(Calendar.MONTH) + 1;
        int day = cal.get(Calendar.DAY_OF_MONTH);
        return cal.get(Calendar.YEAR)+"-"+String.format(Locale.ROOT,"%02d", month)+"-"+String.format(Locale.ROOT,"%02d", day);
    }

    public String getTime() {
        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(timestamp * 1000);
        return String.format(Locale.ROOT, "%02d", cal.get(Calendar.HOUR_OF_DAY))+
                ":"+String.format(Locale.ROOT, "%02d", cal.get(Calendar.MINUTE));
    }

    public String getWhat() {
        return what;
    }

    public void setWhat(String what) {
        this.what = what;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public String getRepeat() {
        return repeat;
    }

    public void setRepeat(String repeat) {
        this.repeat = repeat;
    }

    public String getPaymentMode() {
        return paymentMode;
    }

    public void setPaymentMode(String paymentMode) {
        this.paymentMode = paymentMode;
    }

    public int getPaymentModeRemoteId() {
        return paymentModeRemoteId;
    }

    public void setPaymentModeRemoteId(int paymentModeRemoteId) {
        this.paymentModeRemoteId = paymentModeRemoteId;
    }

    public int getCategoryRemoteId() {
        return categoryRemoteId;
    }

    public void setCategoryRemoteId(int categoryId) {
        this.categoryRemoteId = categoryId;
    }

    @Override
    public String toString() {
        // key_id, key_remoteId, key_projectid, key_payer_remoteId, key_amount, key_date, key_what, key_repeat
        return "#DBBill" + getId() + "/" + this.remoteId + "," + this.projectId
                + ", " + this.payerId + ", " + this.amount + ", " + this.timestamp + ", "
                + this.what + ", " + this.state + ", " + this.repeat + ", " + this.paymentMode + ", " + this.categoryRemoteId;
    }

    @Override
    public boolean isSection() {
        return false;
    }
}
