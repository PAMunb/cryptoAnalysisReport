package net.eneiluj.moneybuster.android.activity;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.MenuItem;
import android.widget.Toast;

import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;

import net.eneiluj.moneybuster.android.fragment.EditBillFragment;
import net.eneiluj.moneybuster.model.DBBill;
import net.eneiluj.moneybuster.model.DBBillOwer;
import net.eneiluj.moneybuster.model.DBMember;
import net.eneiluj.moneybuster.model.ProjectType;
import net.eneiluj.moneybuster.persistence.MoneyBusterSQLiteOpenHelper;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class EditBillActivity extends AppCompatActivity implements EditBillFragment.BillFragmentListener {

    public static final String PARAM_BILL_ID = "billId";
    public static final String PARAM_PROJECT_ID = "projectId";
    public static final String PARAM_PROJECT_TYPE = "projectType";
    public static final String PARAM_BILL_ID_TO_DUPLICATE = "billToDuplicate";

    protected MoneyBusterSQLiteOpenHelper db;

    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.ROOT);

    protected EditBillFragment fragment;

    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (savedInstanceState == null) {
            launchBillFragment();
        } else {
            fragment = (EditBillFragment) getSupportFragmentManager().findFragmentById(android.R.id.content);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Log.d(getClass().getSimpleName(), "onNewIntent: " + intent.getLongExtra(PARAM_BILL_ID, 0));
        setIntent(intent);
        if (fragment != null) {
            getSupportFragmentManager().beginTransaction().detach(fragment).commit();
            fragment = null;
        }
        launchBillFragment();
    }

    protected long getBillId() {
        return getIntent().getLongExtra(PARAM_BILL_ID, 0);
    }

    protected long getProjectId() {
        return getIntent().getLongExtra(PARAM_PROJECT_ID, 0);
    }

    protected ProjectType getProjectType() {
        String type = getIntent().getStringExtra(PARAM_PROJECT_TYPE);
        if (type != null && type.length() > 0) {
            return ProjectType.getTypeById(type);
        } else {
            return ProjectType.LOCAL;
        }
    }

    /**
     * Starts the EditBillFragment for an existing bill or a new bill
     */
    private void launchBillFragment() {
        long billId = getBillId();
        if (billId > 0) {
            launchExistingBill(billId);
        } else {
            launchNewBill(getProjectId());
        }
    }

    /**
     * Starts a {@link EditBillFragment} for an existing bill.
     *
     * @param billId ID of the existing bill.
     */

    protected void launchExistingBill(long billId) {
        Fragment.SavedState savedState = null;
        if (fragment != null) {
            savedState = getSupportFragmentManager().saveFragmentInstanceState(fragment);
        }
        fragment = EditBillFragment.newInstance(billId, getProjectType());
        if (savedState != null) {
            fragment.setInitialSavedState(savedState);
        }
        getSupportFragmentManager().beginTransaction().replace(android.R.id.content, fragment).commit();
    }

    /**
     * Starts the {@link EditBillFragment} with a new bill.
     *
     */
    protected void launchNewBill(long projectId) {
        Intent intent = getIntent();

        long billIdToDuplicate = intent.getLongExtra(PARAM_BILL_ID_TO_DUPLICATE, 0);

        DBBill newBill;
        if (billIdToDuplicate == 0) {
            long newTimestamp = System.currentTimeMillis() / 1000;
            newBill = new DBBill(0, 0, projectId, 0, 0, newTimestamp,
                    "", DBBill.STATE_ADDED, DBBill.NON_REPEATED,
                    DBBill.PAYMODE_NONE, DBBill.CATEGORY_NONE, "", DBBill.PAYMODE_ID_NONE);
            fragment = EditBillFragment.newInstanceWithNewBill(newBill, getProjectType());
        } else {
            db = MoneyBusterSQLiteOpenHelper.getInstance(this);
            DBBill btd = db.getBill(billIdToDuplicate);
            newBill = new DBBill(0, 0, projectId, btd.getPayerId(), btd.getAmount(),
                    btd.getTimestamp() + 1, btd.getWhat(), DBBill.STATE_ADDED,
                    btd.getRepeat(), btd.getPaymentMode(), btd.getCategoryRemoteId(),
                    btd.getComment(), btd.getPaymentModeRemoteId());
            List<DBBillOwer> btdOwers = btd.getBillOwers();
            List<DBBillOwer> newBillOwers = new ArrayList<>();
            for (DBBillOwer btdOwer : btdOwers) {
                long mid = btdOwer.getMemberId();
                DBMember member = db.getMember(mid);
                if (member.isActivated()) {
                    newBillOwers.add(btdOwer);
                }
            }
            newBill.setBillOwers(newBillOwers);
            fragment = EditBillFragment.newInstanceWithDuplicatedBill(newBill, getProjectType());
        }

        getSupportFragmentManager().beginTransaction().replace(android.R.id.content, fragment).commit();
    }

    @Override
    public void onBackPressed() {
        fragment.onBackPressed();
        //close();
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:
                fragment.onBackPressed();
                //close();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    /**
     * Send result and closes the Activity
     */
    public void close() {
        fragment.onCloseBill();
        finish();
    }

    public void closeOnSave(long billId) {
        fragment.onCloseBill();
        final Intent data = new Intent();
        data.putExtra(BillsListViewActivity.SAVED_BILL_ID, billId);
        setResult(RESULT_OK, data);
        finish();
    }

    public void closeAndDuplicate(long billId) {
        fragment.onCloseBill();
        final Intent data = new Intent();
        data.putExtra(BillsListViewActivity.BILL_TO_DUPLICATE, billId);
        setResult(RESULT_OK, data);
        finish();
    }

    public void closeOnDelete(long billId) {
        fragment.onCloseBill();
        final Intent data = new Intent();
        data.putExtra(BillsListViewActivity.DELETED_BILL, billId);
        setResult(RESULT_OK, data);
        finish();
    }

    public void onBillUpdated(DBBill bill) {
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            //actionBar.setTitle();
            actionBar.setSubtitle("[" + getFormattedDate(bill.getDate()) + "] " + bill.getAmount() + " (" + bill.getWhat() + ")");
        }
    }

    protected void showToast(CharSequence text, int duration) {
        Context context = getApplicationContext();
        Toast toast = Toast.makeText(context, text, duration);
        toast.show();
    }
    private String getFormattedDate(String stringDate) {
        try {
            Date date = sdf.parse(stringDate);
            java.text.DateFormat dateFormat = android.text.format.DateFormat.getDateFormat(this);
           return dateFormat.format(date);
        } catch (Exception e) {
            return stringDate;
        }
    }
}