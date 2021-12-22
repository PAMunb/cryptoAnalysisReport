package net.eneiluj.moneybuster.model;

import android.content.SharedPreferences;
import android.text.Html;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.preference.PreferenceManager;
import androidx.recyclerview.widget.RecyclerView;

import net.eneiluj.moneybuster.R;
import net.eneiluj.moneybuster.android.activity.BillsListViewActivity;
import net.eneiluj.moneybuster.android.ui.TextDrawable;
import net.eneiluj.moneybuster.persistence.MoneyBusterSQLiteOpenHelper;
import net.eneiluj.moneybuster.util.SupportUtil;
import net.eneiluj.moneybuster.util.ThemeUtils;

import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import static androidx.recyclerview.widget.RecyclerView.NO_POSITION;

public class ItemAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {

    private static final String TAG = ItemAdapter.class.getSimpleName();

    private static final int section_type = 0;
    private static final int bill_type = 1;

    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.ROOT);

    private final BillClickListener billClickListener;
    private List<Item> itemList;
    private List<Integer> selected;
    private MoneyBusterSQLiteOpenHelper db;
    private float avatarRadius;
    private SharedPreferences prefs;
    private ProjectType projectType;

    public ItemAdapter(@NonNull BillClickListener billClickListener, MoneyBusterSQLiteOpenHelper db) {
        this.itemList = new ArrayList<>();
        this.selected = new ArrayList<>();
        this.billClickListener = billClickListener;
        this.db = db;
        this.prefs = PreferenceManager.getDefaultSharedPreferences(db.getContext());
        this.avatarRadius = db.getContext().getResources().getDimension(R.dimen.avatar_radius);
    }

    public void setProjectType(ProjectType type) {
        this.projectType = type;
    }

    /**
     * Updates the item list and notifies respective view to update.
     *
     * @param itemList List of items to be set
     */
    public void setItemList(@NonNull List<Item> itemList) {
        this.itemList = itemList;
        notifyDataSetChanged();
    }

    /**
     * Adds the given bill to the top of the list.
     *
     * @param bill that should be added.
     */
    public void add(@NonNull DBBill bill) {
        itemList.add(0, bill);
        notifyItemInserted(0);
        notifyItemChanged(0);
    }

    /**
     * Replaces a bill with an updated version
     *
     * @param bill with the changes.
     * @param position position in the list of the node
     */
    public void replace(@NonNull DBBill bill, int position) {
        itemList.set(position, bill);
        notifyItemChanged(position);
    }

    /**
     * Removes all items from the adapter.
     */
    public void removeAll() {
        itemList.clear();
        notifyDataSetChanged();
    }

    // Create new views (invoked by the layout manager)
    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View v;
        if (viewType == section_type) {
            v = LayoutInflater.from(parent.getContext()).inflate(R.layout.fragment_bills_list_section_item, parent, false);
            return new SectionViewHolder(v);
        } else {
            v = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.fragment_bills_list_bill_item, parent, false);
            return new BillViewHolder(v);
        }
    }

    // Replace the contents of a view (invoked by the layout manager)
    @Override
    public void onBindViewHolder(final RecyclerView.ViewHolder holder, int position) {
        // - get element from your dataset at this position
        // - replace the contents of the view with that element
        Item item = itemList.get(position);
        if (item.isSection()) {
            SectionItem section = (SectionItem) item;
            ((SectionViewHolder) holder).sectionTitle.setText(section.geTitle());
        } else {
            final DBBill bill = (DBBill) item;
            final BillViewHolder nvHolder = ((BillViewHolder) holder);
            nvHolder.billSwipeable.setAlpha(1.0f);
            String whatPrefix = "";
            // payment mode char
            String oldPaymentMode = bill.getPaymentMode();
            int newPaymentModeId = bill.getPaymentModeRemoteId();
            DBPaymentMode pm = db.getPaymentMode(newPaymentModeId, bill.getProjectId());
            if (pm != null) {
                whatPrefix += pm.getIcon() + " ";
            // give priority to new IDs (hardcoded pms)
            } else if (DBBill.PAYMODE_ID_CARD == newPaymentModeId) {
                whatPrefix += "\uD83D\uDCB3 ";
            } else if (DBBill.PAYMODE_ID_CASH == newPaymentModeId) {
                whatPrefix += "💵 ";
            } else if (DBBill.PAYMODE_ID_CHECK == newPaymentModeId) {
                whatPrefix += "🎫 ";
            } else if (DBBill.PAYMODE_ID_TRANSFER == newPaymentModeId) {
                whatPrefix += "⇄ ";
            } else if (DBBill.PAYMODE_ID_ONLINE_SERVICE == newPaymentModeId) {
                whatPrefix += "\uD83C\uDF0E ";
            // then if no new ID check if old ID is set
            } else if (DBBill.PAYMODE_CARD.equals(oldPaymentMode)) {
                whatPrefix += "\uD83D\uDCB3 ";
            } else if (DBBill.PAYMODE_CASH.equals(oldPaymentMode)) {
                whatPrefix += "💵 ";
            } else if (DBBill.PAYMODE_CHECK.equals(oldPaymentMode)) {
                whatPrefix += "🎫 ";
            } else if (DBBill.PAYMODE_TRANSFER.equals(oldPaymentMode)) {
                whatPrefix += "⇄ ";
            } else if (DBBill.PAYMODE_ONLINE_SERVICE.equals(oldPaymentMode)) {
                whatPrefix += "\uD83C\uDF0E ";
            }
            // category char
            int categoryRemoteId = bill.getCategoryRemoteId();
            DBCategory cat = db.getCategory(categoryRemoteId, bill.getProjectId());
            if (cat != null) {
                whatPrefix += cat.getIcon() + " ";
            // we keep hardcoded here because of local projects
            // and because new MB + old Cospend might need it
            } else if (categoryRemoteId == DBBill.CATEGORY_GROCERIES) {
                whatPrefix += "\uD83D\uDED2 ";
            } else if (categoryRemoteId == DBBill.CATEGORY_LEISURE) {
                whatPrefix += "\uD83C\uDF89 ";
            } else if (categoryRemoteId == DBBill.CATEGORY_RENT) {
                whatPrefix += "\uD83C\uDFE0 ";
            } else if (categoryRemoteId == DBBill.CATEGORY_BILLS) {
                whatPrefix += "\uD83C\uDF29 ";
            } else if (categoryRemoteId == DBBill.CATEGORY_CULTURE) {
                whatPrefix += "\uD83D\uDEB8 ";
            } else if (categoryRemoteId == DBBill.CATEGORY_HEALTH) {
                whatPrefix += "\uD83D\uDC9A ";
            } else if (categoryRemoteId == DBBill.CATEGORY_SHOPPING) {
                whatPrefix += "\uD83D\uDECD ";
            } else if (categoryRemoteId == DBBill.CATEGORY_REIMBURSEMENT) {
                whatPrefix += "\uD83D\uDCB0 ";
            } else if (categoryRemoteId == DBBill.CATEGORY_RESTAURANT) {
                whatPrefix += "\uD83C\uDF74 ";
            } else if (categoryRemoteId == DBBill.CATEGORY_ACCOMODATION) {
                whatPrefix += "\uD83D\uDECC ";
            } else if (categoryRemoteId == DBBill.CATEGORY_TRANSPORT) {
                whatPrefix += "\uD83D\uDE8C ";
            } else if (categoryRemoteId == DBBill.CATEGORY_SPORT) {
                whatPrefix += "\uD83C\uDFBE ";
            }
            nvHolder.billTitle.setText(Html.fromHtml(whatPrefix + bill.getWhat()));

            if (selected.contains(position)) {
                nvHolder.avatar.setImageDrawable(ContextCompat.getDrawable(db.getContext(), R.drawable.ic_check_circle_gray_24dp));
            } else {
                try {
                    DBMember m = db.getMember(bill.getPayerId());
                    if (m.getAvatar() == null || m.getAvatar().equals("")) {
                        nvHolder.avatar.setImageDrawable(
                                TextDrawable.createNamedAvatar(
                                        m.getName(), avatarRadius,
                                        m.getR(), m.getG(), m.getB(),
                                        !m.isActivated()
                                )
                        );
                    } else {
                        nvHolder.avatar.setImageDrawable(
                                ThemeUtils.getMemberAvatarDrawable(
                                        db.getContext(), m.getAvatar(), !m.isActivated()
                                )
                        );
                    }
                } catch (NoSuchAlgorithmException e) {
                    nvHolder.avatar.setImageDrawable(null);
                }
            }

            setFormattedDatetime(nvHolder.billDate, nvHolder.billTime, bill);

            Log.d(TAG, "[get member of project " + bill.getProjectId() + " with remoteid : "+bill.getPayerId()+"]");
            double rAmount = Math.round(bill.getAmount() * 100.0 ) / 100.0;
            String subtitle = SupportUtil.normalNumberFormat.format(rAmount);
            subtitle += " (" + db.getMember(bill.getPayerId()).getName();
            subtitle += " → ";
            for (long boRId : bill.getBillOwersIds()) {
                String name = db.getMember(boRId).getName();
                subtitle += name + ", ";
            }
            subtitle = subtitle.replaceAll(", $", "");
            subtitle += ")";

            nvHolder.billSubtitle.setText(Html.fromHtml(subtitle));

            boolean isProjectLocal = ProjectType.LOCAL.equals(projectType);
            nvHolder.syncIcon.setVisibility((isProjectLocal || bill.getState() == DBBill.STATE_OK) ? View.INVISIBLE : View.VISIBLE);

            String repeat = bill.getRepeat() == null ? DBBill.NON_REPEATED : bill.getRepeat();
            nvHolder.repeatIcon.setVisibility(DBBill.NON_REPEATED.equals(repeat) ? View.GONE : View.VISIBLE);

            if (selected.contains(position)) {
                nvHolder.billSwipeable.setBackgroundResource(R.color.bg_highlighted);
            } else {
                nvHolder.billSwipeable.setBackgroundResource(R.color.bg_normal);
            }
        }
    }

    private void setFormattedDatetime(TextView billDate, TextView billTime, DBBill bill) {
        String stringDate = bill.getDate();
        try {
            Date date = sdf.parse(stringDate);
            java.text.DateFormat dateFormat = android.text.format.DateFormat.getDateFormat(db.getContext());
            Log.v(TAG, "set formatted date item orig "+stringDate+" transformed to "+dateFormat.format(date));
            billDate.setText(Html.fromHtml(dateFormat.format(date)));
        } catch (Exception e) {
            billDate.setText(Html.fromHtml(stringDate));
        }
        /*if (!projectType.equals(ProjectType.IHATEMONEY)) {
            billTime.setText(bill.getTime());
        } else {*/
            billTime.setText("");
        //}
    }

    public boolean select(Integer position) {
        return !selected.contains(position) && selected.add(position);
    }

    public void clearSelection() {
        selected.clear();
    }

    @NonNull
    public List<Integer> getSelected() {
        return selected;
    }

    public boolean deselect(Integer position) {
        for (int i = 0; i < selected.size(); i++) {
            if (selected.get(i).equals(position)) {
                //position was selected and removed
                selected.remove(i);
                return true;
            }
        }
        // position was not selected
        return false;
    }

    public Item getItem(int billPosition) {
        if (billPosition >= 0 && billPosition < itemList.size()) {
            if (BillsListViewActivity.DEBUG) { Log.d(TAG, "[GETITEM " + billPosition + "/"+itemList.size()+"]"); }
            return itemList.get(billPosition);
        } else {
            return null;
        }
    }

    public void remove(@NonNull Item item) {
        itemList.remove(item);
        notifyDataSetChanged();
    }

    @Override
    public int getItemCount() {
        return itemList.size();
    }

    @Override
    public int getItemViewType(int position) {
        return getItem(position).isSection() ? section_type : bill_type;
    }

    public interface BillClickListener {
        void onBillClick(int position, View v);

        boolean onBillLongClick(int position, View v);
    }

    public class BillViewHolder extends RecyclerView.ViewHolder implements View.OnLongClickListener, View.OnClickListener {
        public View billSwipeable;
        View billSwipeFrame;
        ImageView avatar;
        TextView billTextToggleLeft;
        ImageView billDeleteRight;
        TextView billTitle;
        TextView billDate;
        TextView billTime;
        TextView billSubtitle;
        ImageView syncIcon;
        ImageView repeatIcon;

        private BillViewHolder(View v) {
            super(v);
            this.billSwipeFrame = v.findViewById(R.id.billSwipeFrame);
            this.billSwipeable = v.findViewById(R.id.billSwipeable);
            this.billTextToggleLeft = v.findViewById(R.id.billTextToggleLeft);
            this.billDeleteRight = v.findViewById(R.id.billDeleteRight);
            this.avatar = v.findViewById(R.id.avatar);
            this.billTitle = v.findViewById(R.id.billTitle);
            this.billDate = v.findViewById(R.id.billDate);
            this.billTime = v.findViewById(R.id.billTime);
            this.billSubtitle = v.findViewById(R.id.billExcerpt);
            this.syncIcon = v.findViewById(R.id.syncIcon);
            this.repeatIcon = v.findViewById(R.id.repeatIcon);
            v.setOnClickListener(this);
            v.setOnLongClickListener(this);
        }

        @Override
        public void onClick(View v) {
            final int adapterPosition = getAdapterPosition();
            if (adapterPosition != NO_POSITION) {
                billClickListener.onBillClick(adapterPosition, v);
            }
        }

        @Override
        public boolean onLongClick(View v) {
            return billClickListener.onBillLongClick(getAdapterPosition(), v);
        }

        public void showSwipe(boolean left) {
            billTextToggleLeft.setVisibility(left ? View.VISIBLE : View.INVISIBLE);
            billDeleteRight.setVisibility(left ? View.INVISIBLE : View.VISIBLE);
            billSwipeFrame.setBackgroundResource(left ? R.color.bg_warning : R.color.bg_attention);
        }
    }

    public static class SectionViewHolder extends RecyclerView.ViewHolder {
        TextView sectionTitle;

        private SectionViewHolder(View view) {
            super(view);
            sectionTitle = view.findViewById(R.id.sectionTitle);
        }
    }
}